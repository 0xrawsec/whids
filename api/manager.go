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

	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml"

	"github.com/google/uuid"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/gene/v2/reducer"
	"github.com/0xrawsec/golang-misp/misp"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/whids/logger"
)

const (
	// DefaultLogPerm default logfile permission for Manager
	DefaultLogPerm = 0600
	// DefaultManagerLogSize  default size for Manager's logfiles
	DefaultManagerLogSize = utils.Mega * 100
	// DefaultKeySize default size for API key generation
	DefaultKeySize = 64
	// EptAPIDefaultPort default port used by manager's endpoint API
	EptAPIDefaultPort = 1519
	// AdmAPIDefaultPort default port used by manager's admin API
	AdmAPIDefaultPort = 1520
	// DefaultMaxUploadSize default maximum upload size
	DefaultMaxUploadSize = 100 * utils.Mega
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
		return fmt.Errorf("certificate file (%s) not found", t.Cert)
	case !fsutil.IsFile(t.Key):
		return fmt.Errorf("key file (%s) not found", t.Key)
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

// EndpointAPIConfig structure holding configuration for the API used by endpoints
type EndpointAPIConfig struct {
	Host      string `toml:"host" comment:"Hostname or IP where the API should listen to"`
	Port      int    `toml:"port" comment:"Port used by the API"`
	ServerKey string `toml:"server-key" comment:"Server key used to do basic authentication of the server on clients.\n Configure certificate pinning on client offers better security."`
}

// ManagerLogConfig structure to hold manager's logging configuration
type ManagerLogConfig struct {
	Root        string `toml:"root" comment:"Root directory where logfiles are stored"`
	LogBasename string `toml:"logfile" comment:"Logfile name (relative to root) used to store logs"`
	VerboseHTTP bool   `toml:"verbose-http" comment:"Enables verbose HTTP logs\n When disabled beaconing requests are filtered out"`
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
	Database      string            `toml:"db" comment:"Path to store database"`
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

// Manager structure definition
type Manager struct {
	sync.RWMutex
	/* Private */
	db                *sod.DB
	eventStreamer     *EventStreamer
	eventLogger       *logger.EventLogger
	eventSearcher     *logger.EventSearcher
	detectionLogger   *logger.EventLogger
	detectionSearcher *logger.EventSearcher
	endpointAPI       *http.Server
	endpoints         Endpoints
	adminAPI          *http.Server
	users             *Users
	stop              chan bool
	done              bool
	// Gene related members
	geneEng          *engine.Engine
	reducer          *reducer.Reducer
	rules            string // to cache the rules concatenated
	rulesSha256      string // rules integrity check and update
	containers       map[string][]string
	containersSha256 map[string]string

	/* Public */
	Config *ManagerConfig
}

// NewManager creates a new WHIDS manager with a logfile as parameter
func NewManager(c *ManagerConfig) (*Manager, error) {
	var err error
	var objects []sod.Object

	m := Manager{Config: c}
	//logPath := filepath.Join(c.Logging.Root, c.Logging.LogBasename)
	eventDir := filepath.Join(c.Logging.Root, "events")
	m.eventLogger = logger.NewEventLogger(eventDir, c.Logging.LogBasename, utils.Giga)
	m.eventSearcher = logger.NewEventSearcher(eventDir)
	detectionDir := filepath.Join(c.Logging.Root, "detections")
	m.detectionLogger = logger.NewEventLogger(detectionDir, "logs.gz", utils.Giga)
	m.detectionSearcher = logger.NewEventSearcher(detectionDir)

	// database initialization
	m.db = sod.Open(c.Database)

	// Create a new streamer
	m.eventStreamer = NewEventStreamer()

	if c.EndpointAPI.Port <= 0 || c.EndpointAPI.Port > 65535 {
		return nil, fmt.Errorf("manager Endpoint API Error: invalid port to listen to %d", c.EndpointAPI.Port)
	}

	if c.AdminAPI.Port <= 0 || c.AdminAPI.Port > 65535 {
		return nil, fmt.Errorf("manager Admin API Error: invalid port to listen to %d", c.EndpointAPI.Port)
	}

	if err := os.MkdirAll(c.Logging.Root, utils.DefaultPerms); err != nil {
		return nil, fmt.Errorf("failed at creating log directory: %s", err)
	}

	if err := m.initializeDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize manager's database: %w", err)

	}

	// Endpoints initialization
	m.endpoints = NewEndpoints()
	if objects, err = m.db.All(&Endpoint{}); err != nil {
		return nil, err
	}
	for _, o := range objects {
		ept := o.(*Endpoint)
		m.endpoints.Add(ept)
	}

	// Users initialization
	m.users = NewUsers()
	if objects, err = m.db.All(&AdminAPIUser{}); err != nil {
		return nil, err
	}
	for _, o := range objects {
		user := o.(*AdminAPIUser)
		if err = m.users.Add(user); err != nil {
			return nil, err
		}
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
		if err := os.MkdirAll(m.Config.DumpDir, utils.DefaultPerms); err != nil {
			return &m, fmt.Errorf("failed to created dump directory (%s): %s", m.Config.DumpDir, err)
		}
	}
	return &m, nil
}

func (m *Manager) initializeDB() (err error) {
	if err = m.db.Create(&Endpoint{}, &sod.DefaultSchema); err != nil {
		return
	}

	if err = m.db.Create(&AdminAPIUser{}, &sod.DefaultSchema); err != nil {
		return
	}

	archivedReportSchema := sod.DefaultSchema
	archivedReportSchema.ObjectsIndex = sod.NewIndex("Identifier", "ArchivedTimestamp")
	if err = m.db.Create(&ArchivedReport{}, &archivedReportSchema); err != nil {
		return
	}

	return
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
	m.geneEng = e
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
	m.containersSha256[mispContName] = utils.Sha256StringArray(mispContainer)
}

// AddEndpoint adds new endpoint to the manager
func (m *Manager) AddEndpoint(uuid, key string) {
	m.endpoints.Add(NewEndpoint(uuid, key))
}

// UpdateReducer updates the reducer member of the Manager
func (m *Manager) UpdateReducer(identifier string, e *event.EdrEvent) {
	if e.Event.Detection != nil {
		isigs := e.Event.Detection.Signature.Slice()
		sigs := make([]string, 0, len(isigs))

		for _, s := range isigs {
			sigs = append(sigs, s.(string))
		}

		if len(sigs) > 0 {
			m.reducer.Update(e.Timestamp(), identifier, sigs)
		}
	}
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
func (m *Manager) Shutdown() (lastErr error) {
	defer func() { go func() { m.stop <- true }() }()
	if m.done {
		return
	}
	m.done = true
	if m.endpointAPI != nil {
		m.endpointAPI.Shutdown(context.Background())
	}
	if m.adminAPI != nil {
		m.adminAPI.Shutdown(context.Background())
	}

	if err := m.detectionLogger.Close(); err != nil {
		lastErr = err
	}

	if err := m.eventLogger.Close(); err != nil {
		lastErr = err
	}
	return
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
