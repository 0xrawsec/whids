package server

import (
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golog"
	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/ioc"
	"github.com/0xrawsec/whids/sysmon"
	"github.com/0xrawsec/whids/tools"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml/v2"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/gene/v2/reducer"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/whids/logger"
)

const (
	// IoCContainerName default container name to store manager's IoCs
	IoCContainerName = "edr_iocs"
)

var (
	noBracketGuidRe = regexp.MustCompile(`(?i:[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12})`)
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
// source: https://blog.golang.org/context/userip/userip.go
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

func (m *Manager) gunzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			var err error
			if r.Body, err = gzip.NewReader(r.Body); err != nil {
				http.Error(w, "Cannot create gzip reader", http.StatusInternalServerError)
				m.Logger.Errorf("Failed to create reader to uncompress request: %s", err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

//////////////////// TLSConfig

// TLSConfig structure definition
type TLSConfig struct {
	Cert string `toml:"cert" comment:"Path to the certificate file to use for TLS connections"`
	Key  string `toml:"key" comment:"Path to the key to use for TLS connection"`
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

// EndpointAPIConfig structure holding configuration for the API used by endpoints
type EndpointAPIConfig struct {
	Host      string `toml:"host" comment:"Hostname or IP where the API should listen to"`
	Port      int    `toml:"port" comment:"Port used by the API"`
	ServerKey string `toml:"server-key" comment:"Server key used to do basic authentication of the server on clients.\n Configure certificate pinning on client offers better security."`
}

// ManagerLogConfig structure to hold manager's logging configuration
type ManagerLogConfig struct {
	Root        string `toml:"root" comment:"Root directory where logfiles are stored"`
	LogBasename string `toml:"logfile" comment:"Logfile name (relative to root) used to store logs"`
	VerboseHTTP bool   `toml:"verbose-http" comment:"Enables verbose HTTP logs\n When disabled beaconing requests are filtered out"`
}

// ManagerConfig defines manager's configuration structure
type ManagerConfig struct {
	// TOML strings need to be first otherwise issue parsing back config
	Database    string            `toml:"db" comment:"Path to store database"`
	Repair      bool              `toml:"repair-db" comment:"Attempt to repair broken database"`
	DumpDir     string            `toml:"dump-dir" comment:"Directory where to dump artifacts collected on hosts"`
	AdminAPI    AdminAPIConfig    `toml:"admin-api" comment:"Settings to configure administrative API (not supposed to be reachable by endpoints)"`
	EndpointAPI EndpointAPIConfig `toml:"endpoint-api" comment:"Settings to configure API used by endpoints"`
	Logging     ManagerLogConfig  `toml:"logging" comment:"Logging settings"`
	TLS         TLSConfig         `toml:"tls" comment:"TLS settings. Leave empty, not to use TLS"`
	path        string
}

// LoadManagerConfig loads the manager configuration from a file
func LoadManagerConfig(path string) (*ManagerConfig, error) {
	mc := ManagerConfig{}
	b, err := os.ReadFile(path)
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

// EndpointAPIUrl returns the URL of the Endpoint API
func (mc *ManagerConfig) EndpointAPIUrl() string {
	proto := "https"
	if mc.TLS.Empty() {
		proto = "http"
	}

	return fmt.Sprintf("%s://%s:%d", proto, mc.EndpointAPI.Host, mc.EndpointAPI.Port)
}

// EndpointAPIUrl returns the URL of the Admin API
func (mc *ManagerConfig) AdminAPIUrl() string {
	proto := "https"
	if mc.TLS.Empty() {
		proto = "http"
	}

	return fmt.Sprintf("%s://%s:%d", proto, mc.AdminAPI.Host, mc.AdminAPI.Port)
}

// Save saves the configuration to a path specified by the path member of the structure
func (mc *ManagerConfig) Save() error {
	b, err := toml.Marshal(mc)
	if err != nil {
		return err
	}
	return os.WriteFile(mc.path, b, 0650)
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
	adminAPI          *http.Server
	stop              chan bool
	done              bool

	// Gene related members
	gene struct {
		engine  *engine.Engine
		reducer *reducer.Reducer
		rules   string // to cache the rules concatenated
		sha256  string // rules integrity check and update
	}

	iocs *ioc.IoCs

	/* Public */
	Logger *golog.Logger
	Config *ManagerConfig
}

// NewManager creates a new WHIDS manager with a logfile as parameter
func NewManager(c *ManagerConfig) (*Manager, error) {
	var err error

	m := Manager{
		iocs:   ioc.NewIocs(),
		Logger: golog.FromStdout(),
		Config: c}

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

	if err := os.MkdirAll(c.Logging.Root, utils.DefaultFilePerm); err != nil {
		return nil, fmt.Errorf("failed at creating log directory: %s", err)
	}

	if err := m.initializeDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize manager's database: %w", err)
	}

	// initialize IoCs from db
	m.iocs.FromDB(m.db)

	m.stop = make(chan bool)
	if err = c.TLS.Verify(); err != nil && !c.TLS.Empty() {
		return nil, err
	}

	// Gene components initialization
	if err := m.initializeGeneFromDB(); err != nil {
		return &m, fmt.Errorf("manager cannot initialize gene components: %s", err)
	}

	// Dump Directory initialization
	if m.Config.DumpDir != "" && !fsutil.IsDir(m.Config.DumpDir) {
		if err := os.MkdirAll(m.Config.DumpDir, utils.DefaultFilePerm); err != nil {
			return &m, fmt.Errorf("failed to created dump directory (%s): %s", m.Config.DumpDir, err)
		}
	}
	return &m, nil
}

func (m *Manager) createTableOrRepair(o sod.Object, s sod.Schema) (err error) {
	// if everything went fine we return
	if err = m.db.Create(o, s); err == nil {
		return
	}

	// if err is something else than an index corruption error
	if !sod.IsIndexCorrupted(err) {
		return
	}

	// we repair DB if wanted
	if m.Config.Repair {
		return m.db.Repair(o)
	}

	return
}

func (m *Manager) initializeDB() (err error) {

	// Creating Endpoint table
	endpointSchema := sod.DefaultSchema
	endpointSchema.Asynchrone(100, 10*time.Second)
	if err = m.createTableOrRepair(&api.Endpoint{}, endpointSchema); err != nil {
		return
	}

	// Creating AdminAPIUser table
	if err = m.createTableOrRepair(&AdminAPIUser{}, sod.DefaultSchema); err != nil {
		return
	}

	// Creating IOC table
	if err = m.createTableOrRepair(&ioc.IOC{}, sod.DefaultSchema); err != nil {
		return
	}

	// Creating Sysmon config table
	if err = m.createTableOrRepair(&sysmon.Config{}, sod.DefaultSchema); err != nil {
		return
	}

	// Creating Tools table
	if err = m.createTableOrRepair(&tools.Tool{}, sod.DefaultSchema); err != nil {
		return
	}

	// Create schema for ArchivedReport
	// we need to set indexed fields manually here as we don't
	// have access to ReducedStats structure
	archReportsDesc := sod.FieldDescriptors(&api.ArchivedReport{})
	archReportsDesc.Constraint("Identifier", sod.Constraints{Index: true})
	archReportsDesc.Constraint("ArchivedTimestamp", sod.Constraints{Index: true})
	archivedReportSchema := sod.NewCustomSchema(archReportsDesc, sod.DefaultExtension)

	if err = m.createTableOrRepair(&api.ArchivedReport{}, archivedReportSchema); err != nil {
		return
	}

	// Create schema for EdrRule
	rulesDesc := sod.FieldDescriptors(&api.EdrRule{})
	rulesDesc.Constraint("Name", sod.Constraints{Index: true, Unique: true})
	rulesSchema := sod.NewCustomSchema(rulesDesc, ".gen")

	if err = m.createTableOrRepair(&api.EdrRule{}, rulesSchema); err != nil {
		return
	}

	return
}

func (m *Manager) initializeGeneFromDB() error {
	engine := engine.NewEngine()
	engine.SetDumpRaw(true)

	reducer := reducer.NewReducer(engine)

	if objs, err := m.db.All(&api.EdrRule{}); err != nil {
		return err
	} else {
		for _, o := range objs {
			rule := o.(*api.EdrRule)
			if err := engine.LoadRule(&rule.Rule); err != nil {
				return fmt.Errorf("fail to load rule %s: %s", rule.Name, err)
			}
		}
	}

	// we update gene components only if no error is met
	m.gene.engine = engine
	m.gene.reducer = reducer
	m.updateRulesCache()

	return nil

}

func (m *Manager) updateRulesCache() {
	sha256 := sha256.New()
	buf := new(bytes.Buffer)
	for rr := range m.gene.engine.GetRawRule(".*") {
		chunk := []byte(rr + "\n")
		buf.Write(chunk)
		sha256.Write(chunk)
	}
	m.gene.rules = buf.String()
	m.gene.sha256 = hex.EncodeToString(sha256.Sum(nil))
}

// AddCommand sets a command to be executed on endpoint specified by UUID
func (m *Manager) AddCommand(uuid string, c *api.EndpointCommand) error {
	if endpt, ok := m.Endpoint(uuid); ok {
		endpt.Command = c
		return m.db.InsertOrUpdate(endpt)
	}
	return ErrUnkEndpoint
}

// GetCommand gets the command set for an endpoint specified by UUID
func (m *Manager) GetCommand(uuid string) (*api.EndpointCommand, error) {
	if endpt, ok := m.Endpoint(uuid); ok {
		// We return the command of an unmutable endpoint struct
		// so if Command is modified this will not affect Endpoint
		return endpt.Command, nil
	}
	return nil, ErrUnkEndpoint
}

// Endpoint returns an Endpoint pointer from database
// Result must be handled with care as any change to the Endpoint
// might be commited to the database. If an Endpoint needs to be
// modified but changes don't need to be commited, use Endpoint.Copy()
// to work on a copy
func (m *Manager) Endpoint(uuid string) (*api.Endpoint, bool) {
	if o, err := m.db.GetByUUID(&api.Endpoint{}, uuid); err == nil {
		// we return copy to endpoints not to modify cached structures
		return o.(*api.Endpoint), true
	}
	return nil, false
}

// Endpoints returns a slice of Endpoint pointers from database
// Result must be handled with care as any change to the Endpoint
// might be commited to the database. If an Endpoint needs to be
// modified but changes don't need to be commited, use Endpoint.Copy()
// to work on a copy
func (m *Manager) Endpoints() (endpoints []*api.Endpoint, err error) {
	var all []sod.Object

	if all, err = m.db.All(&api.Endpoint{}); err != nil {
		return
	}

	endpoints = make([]*api.Endpoint, 0, len(all))
	for _, o := range all {
		// we return copy to endpoints not to modify cached structures
		endpoints = append(endpoints, o.(*api.Endpoint))
	}

	return
}

func (m *Manager) ImportRules(directory string) (err error) {
	engine := engine.NewEngine()
	engine.SetDumpRaw(true)

	if err = engine.LoadDirectory(directory); err != nil {
		return
	}

	rules := make([]*api.EdrRule, 0, engine.Count())
	for rr := range engine.GetRawRule(".*") {
		rule := &api.EdrRule{}
		if err = json.Unmarshal([]byte(rr), &rule); err != nil {
			return
		}
		rules = append(rules, rule)
	}

	if _, err = m.db.InsertOrUpdateMany(sod.ToObjectSlice(rules)...); err != nil {
		return err
	}

	return
}

// CreateNewAdminAPIUser creates a new user in the user able to access admin API in database.
func (m *Manager) CreateNewAdminAPIUser(user *AdminAPIUser) (err error) {
	if err = m.db.InsertOrUpdate(user); err != nil && !sod.IsUnique(err) {
		return err
	} else if sod.IsUnique(err) {
		err = errors.New("user with same Identifier or Uuid or Key already exists in database")
		return
	}

	return

}

// AddEndpoint adds new endpoint to the manager
func (m *Manager) AddEndpoint(uuid, key string) {
	m.db.InsertOrUpdate(api.NewEndpoint(uuid, key))
}

func (m *Manager) AddIoCs(iocs []*ioc.IOC) (err error) {

	// we preprocess to update existing IOCs
	insert := make([]*ioc.IOC, 0, len(iocs))
	for _, i := range iocs {
		// we need to apply transformation before searching otherwise we
		// might not find some values which have been transformed
		i.Transform()
		search := m.db.Search(&ioc.IOC{},
			"Uuid", "=", i.Uuid)
		if o, err := search.One(); err == nil {
			// in order to update existing IOCs
			i.Initialize(o.UUID())
		}

		insert = append(insert, i)
	}

	// Do bulk insertion
	if _, err = m.db.InsertOrUpdateMany(sod.ToObjectSlice(insert)...); err != nil {
		//wt.Write(admErr(err))
		return
	}

	// Add IoCs to sync with endpoints
	m.iocs.Add(insert...)

	return
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
			m.gene.reducer.Update(e.Timestamp(), identifier, sigs)
		}
	}
}

func (m *Manager) logAPIErrorf(fmt string, i ...interface{}) {
	funcName := "unk.UnknownFunc"
	if pc, _, _, ok := runtime.Caller(1); ok {
		split := strings.Split(runtime.FuncForPC(pc).Name(), "/")
		funcName = split[len(split)-1]
	}

	msg := format("%s: %s", funcName, format(fmt, i...))

	m.Logger.Error(msg)
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

	if err := m.db.Close(); err != nil {
		lastErr = err
	}

	return
}

// Run starts a new thread spinning the receiver
func (m *Manager) Run() {
	m.runEndpointAPI()
	m.runAdminAPI()
}
