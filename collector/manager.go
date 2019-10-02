package collector

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/fsutil/logfile"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/golang-utils/scanner"
	"github.com/0xrawsec/mux"
)

const (
	// DefaultLogPerm default logfile permission for Manager
	DefaultLogPerm = 0600
	// DefaultManagerLogSize  default size for Manager's logfiles
	DefaultManagerLogSize = logfile.MB * 100
	// DefaultKeySize default size for API key generation
	DefaultKeySize = 32
	// DefaultPort default port used by Manager
	DefaultPort = "1519"
)

var (
	guidRe      = regexp.MustCompile(`(?i:\{[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}\})`
	eventHashRe = regexp.MustCompile(`[a-f0-9]{32,}`) // at least md5
	filenameRe  = regexp.MustCompile(`[\w\s\.-]+`)
)

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

	// Create directory if don't exist
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
	Cert string `json:"cert"`
	Key  string `json:"key"`
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

// KeyGen is an API key generator, supposed to generate an [[:alnum:]] key
func KeyGen(size int) string {
	rand.Seed(time.Now().Unix())
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

// ManagerConfig defines manager's configuration structure
type ManagerConfig struct {
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Logfile       string    `json:"logfile"`
	Key           string    `json:"key"`
	Authorized    []string  `json:"authorized"`
	TLS           TLSConfig `json:"tls"`
	RulesDir      string    `json:"rules-dir"`
	DumpDir       string    `json:"dump-dir"`
	ContainersDir string    `json:"containers-dir"`
}

// Manager structure definition
type Manager struct {
	Host          string
	Port          string
	key           string
	dumpDir       string
	rulesDir      string
	containersDir string
	authorized    datastructs.SyncedSet
	logfile       logfile.LogFile
	tls           TLSConfig
	srv           *http.Server
	stop          chan bool
	done          bool
	// Gene related members
	geneEng          *engine.Engine
	rules            string // to cache the rules concatenated
	rulesSha256      string // rules integrity check and update
	containers       map[string][]string
	containersSha256 map[string]string
}

// NewManager creates a new WHIDS manager with a logfile as parameter
func NewManager(c *ManagerConfig) (*Manager, error) {
	var err error
	if c.Port <= 0 || c.Port > 65535 {
		return nil, fmt.Errorf("Manager Error: invalid port to listen to %d", c.Port)
	}

	m := Manager{Host: c.Host, Port: fmt.Sprintf("%d", c.Port)}
	if m.logfile, err = logfile.OpenTimeRotateLogFile(c.Logfile, DefaultLogPerm, time.Hour); err != nil {
		return &m, err
	}
	m.key = c.Key
	m.authorized = datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(c.Authorized)...)
	m.stop = make(chan bool)

	if err = c.TLS.Verify(); err != nil && !c.TLS.Empty() {
		return nil, err
	}
	m.tls = c.TLS

	// Containers initialization
	m.containersDir = c.ContainersDir
	if m.containersDir != "" {
		m.LoadContainers()
	}

	// Gene engine initialization
	m.rulesDir = c.RulesDir
	if err := m.LoadGeneEngine(); err != nil {
		return &m, fmt.Errorf("Manager cannot initialize gene engine: %s", err)
	}

	// Dump Directory initialization
	m.dumpDir = c.DumpDir
	if m.dumpDir != "" && !fsutil.IsDir(m.dumpDir) {
		if err := os.MkdirAll(m.dumpDir, DefaultDirPerm); err != nil {
			return &m, fmt.Errorf("Failed to created dump directory (%s): %s", m.dumpDir, err)
		}
	}

	return &m, nil
}

// LoadGeneEngine make the manager update the gene rules it has to serve
func (m *Manager) LoadGeneEngine() error {
	e := engine.NewEngine(false)
	e.SetDumpRaw(true)
	// Make the engine load rules' directory
	if err := e.LoadDirectory(m.rulesDir); err != nil {
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
	for wi := range fswalker.Walk(m.containersDir) {
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

// AddAuthKey adds an authorized key to access the manager
func (m *Manager) AddAuthKey(key string) {
	m.authorized.Add(key)
}

// Wait the Manager to Shutdown
func (m *Manager) Wait() {
	<-m.stop
}

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
	if m.srv != nil {
		m.srv.Shutdown(nil)
	}
	if m.logfile != nil {
		return m.logfile.Close()
	}
	return nil
}

// Middleware definitions
func logHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// src-ip:src-port http-method http-proto url user-agent authorization  content-length
		fmt.Printf("%s %s %s %s %s \"%s\" \"%s\" %d\n", time.Now().Format(time.RFC3339Nano), r.RemoteAddr, r.Method, r.Proto, r.URL, r.UserAgent(), r.Header.Get("Api-Key"), r.ContentLength)
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) authorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wt http.ResponseWriter, rq *http.Request) {
		//auth := rq.Header.Get("Authorization")
		auth := rq.Header.Get("Api-Key")
		if !m.authorized.Contains(auth) {
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}
		next.ServeHTTP(wt, rq)
	})
}

// Run starts a new thread spinning the receiver
func (m *Manager) Run() {
	go func() {
		// If we fail due to server crash we properly shutdown
		// the receiver to avoid log corruption
		defer func() {
			if err := recover(); err != nil {
				m.Shutdown()
			}
		}()

		rt := mux.NewRouter()
		// Middleware initialization
		// Manages Request Logging
		rt.Use(logHTTPMiddleware)
		// Manages Authorization
		rt.Use(m.authorizationMiddleware)

		// Routes initialization
		// POST based
		rt.HandleFunc(PostLogsURL, m.Collect).Methods("POST")
		rt.HandleFunc(PostDumpURL, m.UploadDump).Methods("POST")

		// GET based
		rt.HandleFunc(GetServerKeyURL, m.ServerKey).Methods("GET")
		rt.HandleFunc(GetRulesURL, m.Rules).Methods("GET")
		rt.HandleFunc(GetRulesSha256URL, m.RulesSha256).Methods("GET")
		rt.HandleFunc(GetContainerURL, m.Container).Methods("GET")
		rt.HandleFunc(GetContainerListURL, m.ContainerList).Methods("GET")
		rt.HandleFunc(GetContainerSha256URL, m.ContainerSha256).Methods("GET")

		uri := fmt.Sprintf("%s:%s", m.Host, m.Port)
		m.srv = &http.Server{
			Handler:      rt,
			Addr:         uri,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		if m.tls.Empty() {
			// Bind to a port and pass our router in
			log.Infof("Running HTTP server on: %s", uri)
			if err := m.srv.ListenAndServe(); err != http.ErrServerClosed {
				log.Panic(err)
			}
		} else {
			// Bind to a port and pass our router in
			log.Infof("Running HTTPS server on: %s", uri)
			if err := m.srv.ListenAndServeTLS(m.tls.Cert, m.tls.Key); err != http.ErrServerClosed {
				log.Panic(err)
			}
		}
	}()
}

// ServerKey HTTP handler used to authenticate server on client side
func (m *Manager) ServerKey(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.key))
}

// Rules HTTP handler used to serve the rules
func (m *Manager) Rules(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.rules))
}

// RulesSha256 returns the sha256 of the latest set of rules loaded into the manager
func (m *Manager) RulesSha256(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.rulesSha256))
}

// UploadDump HTTP handler used to upload dump files from client to manager
func (m *Manager) UploadDump(wt http.ResponseWriter, rq *http.Request) {
	defer rq.Body.Close()

	if m.dumpDir == "" {
		log.Errorf("Upload handler won't dump because no dump directory set")
		http.Error(wt, "Failed to dump file", http.StatusInternalServerError)
		return
	}

	fu := FileUpload{}
	dec := json.NewDecoder(rq.Body)

	if err := dec.Decode(&fu); err != nil {
		log.Errorf("Upload handler failed to decode JSON")
		http.Error(wt, "Failed to decode JSON", http.StatusInternalServerError)
		return
	}

	if err := fu.Dump(m.dumpDir); err != nil {
		log.Errorf("Upload handler failed to dump file (%s): %s", fu.Implode(), err)
		http.Error(wt, "Failed to dump file", http.StatusInternalServerError)
		return
	}
}

// Container HTTP handler serves Gene containers to clients
func (m *Manager) Container(wt http.ResponseWriter, rq *http.Request) {
	vars := mux.Vars(rq)
	if name, ok := vars["name"]; ok {
		if cont, ok := m.containers[name]; ok {
			b, err := json.Marshal(cont)
			if err != nil {
				log.Errorf("Container handler failed to JSON encode container")
				http.Error(wt, "Failed to JSON encode container", http.StatusInternalServerError)
			} else {
				wt.Write(b)
			}
		} else {
			http.Error(wt, "Unavailable container", http.StatusNotFound)
		}
	}
}

// ContainerList HTTP handler to server the list of available containers
func (m *Manager) ContainerList(wt http.ResponseWriter, rq *http.Request) {
	list := make([]string, 0, len(m.containers))
	for cn := range m.containers {
		list = append(list, cn)
	}
	b, err := json.Marshal(list)
	if err == nil {
		wt.Write(b)
	} else {
		log.Errorf("ContainerList handler failed to JSON encode list")
		http.Error(wt, "Failed to JSON encode list", http.StatusInternalServerError)
	}
}

// ContainerSha256 HTTP handler to server the Sha256 of a given container
func (m *Manager) ContainerSha256(wt http.ResponseWriter, rq *http.Request) {
	vars := mux.Vars(rq)
	if name, ok := vars["name"]; ok {
		if sha256, ok := m.containersSha256[name]; ok {
			wt.Write([]byte(sha256))
		} else {
			http.Error(wt, "Unavailable container", http.StatusNotFound)
		}
	}
}

// Collect HTTP handler
func (m *Manager) Collect(wt http.ResponseWriter, rq *http.Request) {
	cnt := 0
	defer rq.Body.Close()

	// Open GZIP body reader
	gzr, err := gzip.NewReader(rq.Body)
	if err != nil {
		http.Error(wt, "Cannot create gzip reader", http.StatusInternalServerError)
		return
	}
	defer gzr.Close()

	// Scans for events
	s := scanner.New(gzr)
	s.InitWhitespace("\n")
	for tok := range s.Tokenize() {
		switch tok {
		case "\n", "":
			break
		default:
			// Todo put there code to validate that logs is JSON format
			log.Debugf("Received Event: %s", tok)
			m.logfile.Write([]byte(fmt.Sprintln(tok)))
			cnt++
		}
	}
	// force logfile to flush events to disk
	//m.logfile.Flush()
	log.Debugf("Count Event Received: %d", cnt)
}
