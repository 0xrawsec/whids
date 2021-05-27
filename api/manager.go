package api

import (
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/pelletier/go-toml"

	"github.com/0xrawsec/gene/reducer"

	"github.com/google/uuid"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-misp/misp"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/fsutil/logfile"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
)

const (
	// DefaultLogPerm default logfile permission for Manager
	DefaultLogPerm = 0600
	// DefaultManagerLogSize  default size for Manager's logfiles
	DefaultManagerLogSize = logfile.MB * 100
	// DefaultKeySize default size for API key generation
	DefaultKeySize = 64
	// EptAPIDefaultPort default port used by manager's endpoint API
	EptAPIDefaultPort = 1519
	// AdmAPIDefaultPort default port used by manager's admin API
	AdmAPIDefaultPort = 1520
)

var (
	guidRe      = regexp.MustCompile(`(?i:\{[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}\})`)
	eventHashRe = regexp.MustCompile(`(?i:[a-f0-9]{32,})`) // at least md5
	filenameRe  = regexp.MustCompile(`[\w\s\.-]+`)
	// MISP container related
	mispContName    = "misp"
	mispTextExports = []string{"md5", "sha1", "sha256", "domain", "hostname"}
)

func init() {
	// tries to initialize the math random generator with random seed
	i, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	rand.Seed(i.Int64())
}

///////////////////// Utils

// IPFromRequest extracts the user IP address from req, if present.
// source: https://blog.golang.org/context/userip/userip.go
func IPFromRequest(req *http.Request) (net.IP, error) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("%q is not IP:port", req.RemoteAddr)
	}

	userIP := net.ParseIP(ip)
	if userIP == nil {
		return nil, fmt.Errorf("%q is not IP:port", req.RemoteAddr)
	}
	return userIP, nil
}

// Middleware definitions
func logHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// src-ip:src-port http-method http-proto url user-agent UUID content-length
		fmt.Printf("%s %s %s %s %s \"%s\" \"%s\" %d\n", time.Now().Format(time.RFC3339Nano), r.RemoteAddr, r.Method, r.Proto, r.URL, r.UserAgent(), r.Header.Get("UUID"), r.ContentLength)
		next.ServeHTTP(w, r)
	})
}

func gunzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			var err error
			if r.Body, err = gzip.NewReader(r.Body); err != nil {
				http.Error(w, "Cannot create gzip reader", http.StatusInternalServerError)
				log.Errorf("Failed to create reader to uncompress request: %s", err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

//////////////////////// FileUpload

// FileUpload structure used to forward files from the client to the manager
type FileUpload struct {
	Name      string `json:"filename"`
	GUID      string `json:"guid"`
	EventHash string `json:"event-hash"`
	Content   []byte `json:"content"`
}

// Validate that the file upload follows the expected format
func (f *FileUpload) Validate() error {
	if !filenameRe.MatchString(f.Name) {
		return fmt.Errorf("Bad filename")
	}
	if !guidRe.MatchString(f.GUID) {
		return fmt.Errorf("Bad guid")
	}
	if !eventHashRe.MatchString(f.EventHash) {
		return fmt.Errorf("Bad event hash")
	}
	return nil
}

// Implode returns the full path of the FileUpload
func (f *FileUpload) Implode() string {
	return filepath.Join(f.GUID, f.EventHash, f.Name)
}

// Dump dumps the FileUpload into the given root directory dir
func (f *FileUpload) Dump(dir string) (err error) {
	// Return error if cannot dump file
	if err = f.Validate(); err != nil {
		return
	}

	dirpath := filepath.Join(dir, f.GUID, f.EventHash)
	fullpath := filepath.Join(dirpath, f.Name)

	// Create directory if doesn't exist
	if !fsutil.IsDir(dirpath) {
		if err = os.MkdirAll(dirpath, DefaultDirPerm); err != nil {
			return
		}
	}

	// If file already exist
	if fsutil.Exists(fullpath) {
		return
	}

	// If file does not exist
	fd, err := os.Create(fullpath)
	if err != nil {
		return
	}
	defer fd.Close()

	if _, err = fd.Write(f.Content); err != nil {
		return
	}

	return
}

//////////////////// TLSConfig

// TLSConfig structure definition
type TLSConfig struct {
	Cert string `toml:"cert" comment:"Path to the certificate file to use for TLS connections"`
	Key  string `toml:"key" comment:"Path to the key to use for TLS connection"`
}

// Empty returns true if current TLSConfig is empty else false
func (t *TLSConfig) Empty() bool {
	return *t == TLSConfig{}
}

// Verify checks whether the files holding cert and key exist
func (t *TLSConfig) Verify() error {
	switch {
	case !fsutil.IsFile(t.Cert):
		return fmt.Errorf("Certificate file (%s) not found", t.Cert)
	case !fsutil.IsFile(t.Key):
		return fmt.Errorf("Key file (%s) not found", t.Key)
	}
	return nil
}

/////////////////////// Manager

// UUIDGen generates a random UUID
func UUIDGen() uuid.UUID {
	uuid := uuid.UUID{}
	for i := 0; i < len(uuid); i++ {
		uuid[i] = uint8(rand.Uint32() >> 24)
	}
	return uuid
}

// KeyGen is an API key generator, supposed to generate an [[:alnum:]] key
func KeyGen(size int) string {
	key := make([]byte, 0, DefaultKeySize)
	for len(key) < size {
		b := uint8(rand.Uint32() >> 24)
		switch {
		case b > 47 && b < 58:
			// 0 to 9
			key = append(key, b)
		case b > 65 && b < 90:
			// A to Z
			key = append(key, b)
		case b > 96 && b < 123:
			// a to z
			key = append(key, b)
		}
	}
	return string(key)
}

// AdminUser structure definition
type AdminUser struct {
	Identifier string `toml:"identifier"`
	Key        string `toml:"key"`
}

// EndpointConfig structure to hold the configuration for one endpoint
type EndpointConfig struct {
	UUID string `toml:"uuid" comment:"Unique client identifier"`
	Key  string `toml:"key" comment:"API key used to authenticate the client"`
}

// EndpointAPIConfig structure holding configuration for the API used by endpoints
type EndpointAPIConfig struct {
	Host      string           `toml:"host" comment:"Hostname or IP where the API should listen to"`
	Port      int              `toml:"port" comment:"Port used by the API"`
	ServerKey string           `toml:"server-key" comment:"Server key used to do basic authentication of the server on clients.\n Configure certificate pinning on client offers better security."`
	Endpoints []EndpointConfig `toml:"endpoints" comment:"Endpoints configurations"`
}

// DelEndpoint deletes an endpoint from the configuration
func (ec *EndpointAPIConfig) DelEndpoint(uuid string) {
	new := make([]EndpointConfig, 0, len(ec.Endpoints)-1)
	for _, e := range ec.Endpoints {
		if e.UUID != uuid {
			new = append(new, e)
		}
	}
	ec.Endpoints = new
}

// ManagerLogConfig structure to hold manager's logging configuration
type ManagerLogConfig struct {
	Root        string `toml:"root" comment:"Root directory where logfiles are stored"`
	LogBasename string `toml:"logfile" comment:"Logfile name (relative to root) used to store logs"`
	EnEnptLogs  bool   `toml:"enable-endpoint-logging" comment:"Enable endpoint logging.In addition to log in the main log file,\n it will store logs individually for each endpoints"`
	VerboseHTTP bool   `toml:"verbose-http" comment:"Enables verbose HTTP logs\n When disabled beaconing requests are filtered out"`
}

// AlertPath builds the path where to store alerts for an endpoint
func (c *ManagerLogConfig) AlertPath(uuid string, date time.Time) string {
	return filepath.Join(c.Root, uuid, date.Format("2006-01-02"), "alerts.gz")
}

// LogPath builds the path where to store logs for an endpoint
func (c *ManagerLogConfig) LogPath(uuid string, date time.Time) string {
	return filepath.Join(c.Root, uuid, date.Format("2006-01-02"), "logs.gz")
}

// MispConfig with TOML tags
type MispConfig struct {
	Proto  string `toml:"protocol" comment:"HTTP protocol to use (http or https)"`
	Host   string `toml:"host" comment:"Hostname or IP address of MISP server"`
	APIKey string `toml:"api-key" comment:"MISP API key"`
}

// ManagerConfig defines manager's configuration structure
type ManagerConfig struct {
	// TOML strings need to be first otherwise issue parsing back config
	RulesDir      string            `toml:"rules-dir" comment:"Gene rule directory\n See: https://github.com/0xrawsec/gene-rules"`
	DumpDir       string            `toml:"dump-dir" comment:"Directory where to dump artifacts collected on hosts"`
	ContainersDir string            `toml:"containers-dir" comment:"Gene rules' containers directory\n (c.f. Gene documentation https://github.com/0xrawsec/gene)"`
	AdminAPI      AdminAPIConfig    `toml:"admin-api" comment:"Settings to configure administrative API (not supposed to be reachable by endpoints)"`
	EndpointAPI   EndpointAPIConfig `toml:"endpoint-api" comment:"Settings to configure API used by endpoints"`
	Logging       ManagerLogConfig  `toml:"logging" comment:"Logging settings"`
	TLS           TLSConfig         `toml:"tls" comment:"TLS settings. Leave empty, not to use TLS"`
	MISP          MispConfig        `toml:"misp" comment:"MISP settings. Use this setting to push IOCs as containers on endpoints"`
	path          string
}

// LoadManagerConfig loads the manager configuration from a file
func LoadManagerConfig(path string) (*ManagerConfig, error) {
	mc := ManagerConfig{}
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal(b, &mc)
	mc.path = path
	return &mc, err
}

// AddEndpointConfig adds a new endpoint with uuid and key to the manager
func (mc *ManagerConfig) AddEndpointConfig(uuid, key string) {
	ec := EndpointConfig{UUID: uuid, Key: key}
	mc.EndpointAPI.Endpoints = append(mc.EndpointAPI.Endpoints, ec)
}

// SetPath exposes the path member for changes
func (mc *ManagerConfig) SetPath(path string) {
	mc.path = path
}

// Save saves the configuration to a path specified by the path member of the structure
func (mc *ManagerConfig) Save() error {
	b, err := toml.Marshal(mc)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(mc.path, b, 0650)
}

// Endpoints structure used to manage endpoints
// This struct looks over complicated for what it
// does but it is because it was more complex before
// and got simplified (too lazy to change it...)
type Endpoints struct {
	sync.RWMutex
	endpoints []*Endpoint
	mapUUID   map[string]int
}

// NewEndpoints creates a new Endpoints structure
func NewEndpoints() Endpoints {
	return Endpoints{
		endpoints: make([]*Endpoint, 0),
		mapUUID:   make(map[string]int),
	}
}

// Add adds an Endpoint to the Endpoints
func (es *Endpoints) Add(e *Endpoint) {
	es.Lock()
	defer es.Unlock()
	es.endpoints = append(es.endpoints, e)
	es.mapUUID[e.UUID] = len(es.endpoints) - 1
}

// DelByUUID deletes an Endpoint by its UUID
func (es *Endpoints) DelByUUID(uuid string) {
	es.Lock()
	defer es.Unlock()
	if i, ok := es.mapUUID[uuid]; ok {
		delete(es.mapUUID, uuid)

		switch {
		case i == 0:
			if len(es.endpoints) == 1 {
				es.endpoints = make([]*Endpoint, 0)
			} else {
				es.endpoints = es.endpoints[i+1:]
			}
		case i == len(es.endpoints)-1:
			es.endpoints = es.endpoints[:i]
		default:
			es.endpoints = append(es.endpoints[:i], es.endpoints[i+1:]...)
		}
	}
}

func (es *Endpoints) HasByUUID(uuid string) bool {
	es.RLock()
	defer es.RUnlock()
	_, ok := es.mapUUID[uuid]
	return ok
}

// GetByUUID returns a reference to the copy of an Endpoint by its UUID
func (es *Endpoints) GetByUUID(uuid string) (*Endpoint, bool) {
	es.RLock()
	defer es.RUnlock()
	if i, ok := es.mapUUID[uuid]; ok {
		return es.endpoints[i].Copy(), true
	}
	return nil, false
}

// GetMutByUUID returns reference to an Endpoint
func (es *Endpoints) GetMutByUUID(uuid string) (*Endpoint, bool) {
	es.RLock()
	defer es.RUnlock()
	if i, ok := es.mapUUID[uuid]; ok {
		return es.endpoints[i], true
	}
	return nil, false
}

// Len returns the number of endpoints
func (es *Endpoints) Len() int {
	es.RLock()
	defer es.RUnlock()
	return len(es.endpoints)
}

// Endpoints returns a list of references to copies of the endpoints
func (es *Endpoints) Endpoints() []*Endpoint {
	es.RLock()
	defer es.RUnlock()
	endpts := make([]*Endpoint, 0, len(es.endpoints))
	for _, e := range es.endpoints {
		endpts = append(endpts, e.Copy())
	}
	return endpts
}

// MutEndpoints returns a list of references of the endpoints
func (es *Endpoints) MutEndpoints() []*Endpoint {
	es.RLock()
	defer es.RUnlock()
	endpts := make([]*Endpoint, len(es.endpoints))
	copy(endpts, es.endpoints)
	return endpts
}

// Manager structure definition
type Manager struct {
	sync.RWMutex
	Config      *ManagerConfig
	logfile     logfile.LogFile
	endpointAPI *http.Server
	endpoints   Endpoints
	adminAPI    *http.Server
	admins      datastructs.SyncedMap
	stop        chan bool
	done        bool
	// Gene related members
	geneEng          *engine.Engine
	reducer          *reducer.Reducer
	rules            string // to cache the rules concatenated
	rulesSha256      string // rules integrity check and update
	containers       map[string][]string
	containersSha256 map[string]string
}

// NewManager creates a new WHIDS manager with a logfile as parameter
func NewManager(c *ManagerConfig) (*Manager, error) {
	var err error

	m := Manager{Config: c}
	logPath := filepath.Join(c.Logging.Root, c.Logging.LogBasename)

	if c.EndpointAPI.Port <= 0 || c.EndpointAPI.Port > 65535 {
		return nil, fmt.Errorf("Manager Endpoint API Error: invalid port to listen to %d", c.EndpointAPI.Port)
	}

	if c.AdminAPI.Port <= 0 || c.AdminAPI.Port > 65535 {
		return nil, fmt.Errorf("Manager Admin API Error: invalid port to listen to %d", c.EndpointAPI.Port)
	}

	if err := os.MkdirAll(c.Logging.Root, DefaultDirPerm); err != nil {
		return nil, fmt.Errorf("Failed at creating log directory: %s", err)
	}

	if m.logfile, err = logfile.OpenTimeRotateLogFile(logPath, DefaultLogPerm, time.Hour); err != nil {
		return nil, err
	}

	m.endpoints = NewEndpoints()
	for _, ec := range c.EndpointAPI.Endpoints {
		m.endpoints.Add(NewEndpoint(ec.UUID, ec.Key))
	}

	m.admins = datastructs.NewSyncedMap()
	for _, au := range c.AdminAPI.Users {
		m.admins.Add(au.Key, au)
	}

	m.stop = make(chan bool)
	if err = c.TLS.Verify(); err != nil && !c.TLS.Empty() {
		return nil, err
	}

	// Containers initialization
	if m.Config.ContainersDir != "" {
		m.LoadContainers()
	}

	// Gene engine initialization
	if err := m.LoadGeneEngine(); err != nil {
		return &m, fmt.Errorf("Manager cannot initialize gene engine: %s", err)
	}

	// Gene Reducer initialization (used to generate reports)
	m.reducer = reducer.NewReducer(m.geneEng)

	// Dump Directory initialization
	if m.Config.DumpDir != "" && !fsutil.IsDir(m.Config.DumpDir) {
		if err := os.MkdirAll(m.Config.DumpDir, DefaultDirPerm); err != nil {
			return &m, fmt.Errorf("Failed to created dump directory (%s): %s", m.Config.DumpDir, err)
		}
	}
	return &m, nil
}

// LoadGeneEngine make the manager update the gene rules it has to serve
func (m *Manager) LoadGeneEngine() error {
	e := engine.NewEngine(false)
	e.SetDumpRaw(true)
	// Make the engine load rules' directory
	if err := e.LoadDirectory(m.Config.RulesDir); err != nil {
		return err
	}
	// We update the engine only if no error loading the rules
	m.geneEng = &e
	m.updateRules()
	return nil
}

// LoadContainers loads the containers into the manager
// the container names is given by the filename without the extension
// Example: /some/random/abspath/blacklist.txt will give blacklist container
func (m *Manager) LoadContainers() {
	m.containers = make(map[string][]string)
	m.containersSha256 = make(map[string]string)
	for wi := range fswalker.Walk(m.Config.ContainersDir) {
		for _, fi := range wi.Files {
			sha256 := sha256.New()
			container := make([]string, 0)
			fp := filepath.Join(wi.Dirpath, fi.Name())
			contName := strings.Split(fi.Name(), ".")[0]
			log.Infof("Loading container \"%s\" from file: %s", contName, fp)
			fd, err := os.Open(fp)
			if err != nil {
				log.Errorf("Failed to load container (%s): %s", fp, err)
			}
			for line := range readers.Readlines(fd) {
				container = append(container, string(line))
				sha256.Write(line)
			}
			m.containers[contName] = container
			m.containersSha256[contName] = hex.EncodeToString(sha256.Sum(nil))
		}
	}
}

func (m *Manager) updateRules() {
	sha256 := sha256.New()
	buf := new(bytes.Buffer)
	for rr := range m.geneEng.GetRawRule(".*") {
		chunk := []byte(rr + "\n")
		buf.Write(chunk)
		sha256.Write(chunk)
	}
	m.rules = buf.String()
	m.rulesSha256 = hex.EncodeToString(sha256.Sum(nil))
}

func (m *Manager) updateMispContainer() {
	c := misp.NewCon(m.Config.MISP.Proto, m.Config.MISP.Host, m.Config.MISP.APIKey)
	mispContainer := make([]string, 0)
	for _, expType := range mispTextExports {
		log.Infof("Downloading %s attributes from MISP", expType)
		exps, err := c.TextExport(expType)
		if err != nil {
			log.Errorf("MISP failed to export %s IDS attributes: %s", expType, err)
			log.Errorf("Aborting MISP container update")
			return
		}
		mispContainer = append(mispContainer, exps...)
	}
	// Update the MISP container
	m.containers[mispContName] = mispContainer
	m.containersSha256[mispContName] = Sha256StringArray(mispContainer)
}

// AddEndpoint adds new endpoint to the manager
func (m *Manager) AddEndpoint(uuid, key string) {
	m.endpoints.Add(NewEndpoint(uuid, key))
}

var (
	sigPath = evtx.Path("/Event/GeneInfo/Signature")
)

// UpdateReducer updates the reducer member of the Manager
func (m *Manager) UpdateReducer(identifier string, e *evtx.GoEvtxMap) {
	iArray, err := e.Get(&sigPath)
	if err != nil {
		// if it is a filtered event it is normal not to have signature field
		return
	}

	sigs := make([]string, 0, len((*iArray).([]interface{})))
	for _, s := range (*iArray).([]interface{}) {
		sigs = append(sigs, s.(string))
	}

	m.reducer.Update(e.TimeCreated(), identifier, sigs)
}

// Wait the Manager to Shutdown
func (m *Manager) Wait() {
	<-m.stop
}

// IsDone returns true when manager is done
func (m *Manager) IsDone() bool {
	return m.done
}

// Shutdown the Manager
func (m *Manager) Shutdown() error {
	defer func() { go func() { m.stop <- true }() }()
	if m.done {
		return nil
	}
	m.done = true
	if m.endpointAPI != nil {
		m.endpointAPI.Shutdown(context.Background())
	}
	if m.adminAPI != nil {
		m.adminAPI.Shutdown(context.Background())
	}
	if m.logfile != nil {
		return m.logfile.Close()
	}
	return nil
}

// Run starts a new thread spinning the receiver
func (m *Manager) Run() {
	go func() {
		for !m.done {
			if m.Config.MISP.Host != "" {
				log.Infof("Starting MISP container update routine")
				m.updateMispContainer()
				log.Infof("MISP container update routine finished")
			}
			time.Sleep(time.Hour)
		}
	}()

	m.runEndpointAPI()
	m.runAdminAPI()
}
