package collector

import (
	"compress/gzip"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/mux"

	"github.com/0xrawsec/golang-utils/datastructs"

	"github.com/0xrawsec/golang-utils/fsutil/logfile"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/scanner"
)

const (
	DefaultLogPerm = 0600
	DefaultLogSize = logfile.MB * 100
	DefaultKeySize = 32
	DefaultPort    = "1519"
)

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

// ManagerConfig defines manager's configuration structure
type ManagerConfig struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Logfile    string    `json:"logfile"`
	Key        string    `json:"key"`
	Authorized []string  `json:"authorized"`
	TLS        TLSConfig `json:"tls"`
}

// Manager structure definition
type Manager struct {
	Host       string
	Port       string
	key        string
	authorized datastructs.SyncedSet
	logfile    *logfile.LogFile
	tls        TLSConfig
	srv        *http.Server
	stop       chan bool
}

// NewManager creates a new WHIDS manager with a logfile as parameter
func NewManager(c *ManagerConfig) (*Manager, error) {
	var err error
	if c.Port <= 0 || c.Port > 65535 {
		return nil, fmt.Errorf("Manager Error: invalid port to listen to %d", c.Port)
	}

	m := Manager{Host: c.Host, Port: fmt.Sprintf("%d", c.Port)}
	m.logfile, err = logfile.OpenFile(c.Logfile, DefaultLogPerm, DefaultLogSize)
	m.key = c.Key
	m.authorized = datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(c.Authorized)...)
	m.stop = make(chan bool)

	if err = c.TLS.Verify(); err != nil && !c.TLS.Empty() {
		return nil, err
	}
	m.tls = c.TLS

	return &m, nil
}

// AddAuthKey adds an authorized key to access the manager
func (m *Manager) AddAuthKey(key string) {
	m.authorized.Add(key)
}

// Wait the Manager to Shutdown
func (m *Manager) Wait() {
	<-m.stop
}

// Shutdown the Manager
func (m *Manager) Shutdown() error {
	defer func() { go func() { m.stop <- true }() }()
	if m.srv != nil {
		m.srv.Shutdown(nil)
	}
	return m.logfile.Close()
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
		// Routes consist of a path and a handler function.
		rt.HandleFunc("/collect", m.Collect).Methods("POST")
		rt.HandleFunc("/key", m.ServerKey).Methods("GET")

		// Middleware initialization
		// Manages Request Logging
		rt.Use(logHTTPMiddleware)
		// Manages Authorization
		rt.Use(m.authorizationMiddleware)

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
			log.Debugf("Received Event: %s", tok)
			m.logfile.WriteString(fmt.Sprintln(tok))
			cnt++
		}
	}
	// force logfile to flush events to disk
	m.logfile.Flush()
	log.Debugf("Count Event Received: %d", cnt)
}
