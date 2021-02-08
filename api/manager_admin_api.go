package api

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/0xrawsec/gene/reducer"
	"github.com/0xrawsec/golang-evtx/evtx"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/mux"
)

func muxGetVar(rq *http.Request, name string) (string, error) {
	vars := mux.Vars(rq)
	if value, ok := vars[name]; ok {
		return value, nil
	}
	return "", fmt.Errorf("Unknown mux variable")
}

func format(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// read posted data and unseriablize it from JSON
func readPostAsJSON(rq *http.Request, i interface{}) error {
	defer rq.Body.Close()
	b, err := ioutil.ReadAll(rq.Body)
	if err != nil {
		return fmt.Errorf("Failed to read POST body: %w", err)
	}
	return json.Unmarshal(b, i)
}

// AdminAPIConfig configuration for Administrative API
type AdminAPIConfig struct {
	Host  string      `json:"host"`
	Port  int         `json:"port"`
	Users []AdminUser `json:"users"`
}

//////////////// AdminAPIResponse

// AdminAPIResponse standard structure to encode any response
// from the AdminAPI
type AdminAPIResponse struct {
	Data  interface{} `json:"data"`
	Error string      `json:"error"`
}

// NewAdminAPIResponse creates a new response from data
func NewAdminAPIResponse(data interface{}) *AdminAPIResponse {
	return &AdminAPIResponse{Data: data}
}

// NewAdminAPIRespError creates a new response from an error
func NewAdminAPIRespError(err error) *AdminAPIResponse {
	return &AdminAPIResponse{Error: fmt.Sprintf("%s", err)}
}

// NewAdminAPIRespErrorString creates a new error response from an error
func NewAdminAPIRespErrorString(err string) *AdminAPIResponse {
	return &AdminAPIResponse{Error: err}
}

// UnmarshalData unmarshals the Data field of the response to an interface
func (r *AdminAPIResponse) UnmarshalData(i interface{}) error {
	b, err := json.Marshal(r.Data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, i)
}

// ToJSON serializes the response to JSON
func (r *AdminAPIResponse) ToJSON() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		safe := AdminAPIResponse{Error: fmt.Sprintf("Failed to encode data to JSON: %s", err)}
		sb, _ := json.Marshal(safe)
		return sb
	}
	return b
}

func admErrStr(s string) []byte {
	return NewAdminAPIRespErrorString(s).ToJSON()
}

/////////////////// Manager functions

func (m *Manager) adminAuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wt http.ResponseWriter, rq *http.Request) {

		auth := rq.Header.Get("Api-Key")
		if !m.admins.Contains(auth) {
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			return
		}
		next.ServeHTTP(wt, rq)
	})
}

func (m *Manager) GetEndpoints(wt http.ResponseWriter, rq *http.Request) {
	switch {
	case rq.Method == "GET":
		// we return the list of all endpoints
		endpoints := make([]*Endpoint, 0, m.endpoints.Len())
		for _, endpt := range m.endpoints.Endpoints() {
			// never show command
			endpt.Command = nil
			endpoints = append(endpoints, endpt)
		}
		wt.Write(NewAdminAPIResponse(endpoints).ToJSON())

	case rq.Method == "PUT":
		endpt := NewEndpoint(CheapUUID().String(), KeyGen(DefaultKeySize))
		m.endpoints.Add(endpt)
		m.Config.AddEndpointConfig(endpt.UUID, endpt.Key)
		if err := m.Config.Save(); err != nil {
			log.Errorf("GetNewEndpoint failed to save config: %s", err)
		}
		wt.Write(NewAdminAPIResponse(endpt).ToJSON())
	}
}

func (m *Manager) GetEndpoint(wt http.ResponseWriter, rq *http.Request) {
	var euuid string
	var err error

	if euuid, err = muxGetVar(rq, "euuid"); err == nil {
		if e, ok := m.endpoints.GetByUUID(euuid); ok {
			if rq.Method == "DELETE" {
				// deleting endpoints from live config
				m.endpoints.DelByUUID(euuid)
				// deleting endpoints from config
				m.Config.EndpointAPI.DelEndpoint(euuid)
				// saving config on disk
				if err := m.Config.Save(); err != nil {
					log.Errorf("GetEndpoint failed to save config: %s", err)
				}
			}
			// we return the endpoint anyway
			wt.Write(NewAdminAPIResponse(e).ToJSON())
		} else {
			wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
		}
	} else {
		wt.Write(admErrStr(format("Failed to parse URL: %s", err)))
	}
}

type CommandAPI struct {
	CommandLine string        `json:"command-line"`
	FetchFiles  []string      `json:"fetch-files"`
	DropFiles   []string      `json:"drop-files"`
	Timeout     time.Duration `json:"timeout"`
}

func (c *CommandAPI) ToCommand() (*Command, error) {
	cmd := NewCommand()
	// adding command line
	if err := cmd.SetCommandLine(c.CommandLine); err != nil {
		return cmd, err
	}

	// adding files to fetch
	for _, ff := range c.FetchFiles {
		cmd.AddFetchFile(ff)
	}

	// adding files to drop on the endpoint
	for _, df := range c.DropFiles {
		cmd.AddDropFileFromPath(df)
	}

	cmd.Timeout = c.Timeout

	return cmd, nil
}

func (m *Manager) EndpointCommand(wt http.ResponseWriter, rq *http.Request) {
	var euuid string
	var err error

	switch rq.Method {
	case "GET":
		if euuid, err = muxGetVar(rq, "euuid"); err != nil {
			wt.Write(NewAdminAPIRespError(err).ToJSON())
		} else {
			if endpt, ok := m.endpoints.GetByUUID(euuid); ok {
				wt.Write(NewAdminAPIResponse(endpt.Command).ToJSON())
			} else {
				wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
			}
		}
	case "POST":
		if euuid, err = muxGetVar(rq, "euuid"); err != nil {
			wt.Write(NewAdminAPIRespError(err).ToJSON())
		} else {
			if endpt, ok := m.endpoints.GetMutByUUID(euuid); ok {
				c := CommandAPI{}
				if err = readPostAsJSON(rq, &c); err != nil {
					wt.Write(NewAdminAPIRespError(err).ToJSON())
				} else {
					tmpCmd, err := c.ToCommand()
					if err != nil {
						wt.Write(admErrStr(format("Failed to create command to execute: %s", err)))
					} else {
						endpt.Command = tmpCmd
						wt.Write(NewAdminAPIResponse(endpt).ToJSON())
					}
				}
			} else {
				wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
			}
		}
	}
}

func (m *Manager) EndpointCommandField(wt http.ResponseWriter, rq *http.Request) {
	var euuid, field string
	var err error

	if euuid, err = muxGetVar(rq, "euuid"); err != nil {
		wt.Write(NewAdminAPIRespError(err).ToJSON())
	} else {
		if endpt, ok := m.endpoints.GetByUUID(euuid); ok {
			if field, err = muxGetVar(rq, "field"); err != nil {
				wt.Write(NewAdminAPIRespError(err).ToJSON())
			} else {
				if endpt.Command != nil {
					// success path
					switch field {
					case "stdout":
						wt.Write(NewAdminAPIResponse(endpt.Command.Stdout).ToJSON())
					case "stderr":
						wt.Write(NewAdminAPIResponse(endpt.Command.Stderr).ToJSON())
					case "error":
						wt.Write(NewAdminAPIResponse(endpt.Command.Error).ToJSON())
					case "completed":
						wt.Write(NewAdminAPIResponse(endpt.Command.Completed).ToJSON())
					case "files":
						wt.Write(NewAdminAPIResponse(endpt.Command.Fetch).ToJSON())
					default:
						wt.Write(admErrStr(format("Field %s not handled", field)))
					}
				} else {
					wt.Write(admErrStr(format("Command is not set for endpoint: %s", euuid)))
				}
			}
		} else {
			wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
		}
	}
}

func (m *Manager) EndpointLogs(wt http.ResponseWriter, rq *http.Request) {
	var err error
	var euuid string
	var start, stop, pivot time.Time
	var delta time.Duration

	logs := make([]evtx.GoEvtxMap, 0)
	pStart := rq.URL.Query().Get("start")
	pStop := rq.URL.Query().Get("stop")

	pPivot := rq.URL.Query().Get("pivot")
	pDelta := rq.URL.Query().Get("delta")

	// Parsing parameters
	if pStart != "" {
		if start, err = time.Parse(time.RFC3339, pStart); err != nil {
			wt.Write(admErrStr("Failed to parse start parameter, it must be RFC3339 formated"))
			return
		}
	}

	if pStop != "" {
		if stop, err = time.Parse(time.RFC3339, pStop); err != nil {
			wt.Write(admErrStr("Failed to parse stop parameter, it must be RFC3339 formated"))
			return
		}
	}

	if pPivot != "" {
		if pivot, err = time.Parse(time.RFC3339, pPivot); err != nil {
			wt.Write(admErrStr("Failed to parse pivot parameter, it must be RFC3339 formated"))
			return
		}
	}

	if pDelta != "" {
		if delta, err = time.ParseDuration(pDelta); err != nil {
			wt.Write(admErrStr("Failed to parse delta parameter, it must be a valid Go time.Duration format"))
			return
		}
	}

	// Controlling parameters
	if start.After(stop) {
		wt.Write(admErrStr("Start date must be before stop date"))
		return
	}

	// Checking compatibility
	if (pStart != "" || pStop != "") && (pPivot != "" || pDelta != "") {
		wt.Write(admErrStr("Incompatible parameters, specify either start/stop or pivot/delta parameters"))
		return
	}

	// Default settings last 24h
	if pStart == "" && pStop == "" && pPivot == "" && pDelta == "" {
		stop = time.Now()
		start = stop.Add(-24 * time.Hour)
	}

	// 10 min delta if delta is not provided
	if pPivot != "" && pDelta == "" {
		delta = time.Minute * 10
	}

	// computing start and stop from pivot and delta
	if !pivot.IsZero() && delta != 0 {
		start = pivot.Add(-delta)
		stop = pivot.Add(+delta)
	}

	if euuid, err = muxGetVar(rq, "euuid"); err != nil {
		wt.Write(NewAdminAPIRespError(err).ToJSON())
	} else {
	Loop:
		for s := start; ; s = s.Add(time.Hour * 24) {
			path := m.Config.Logging.LogPath(euuid, s)

			// if we only want alerts
			if strings.HasSuffix(rq.URL.Path, "/alerts") {
				path = m.Config.Logging.AlertPath(euuid, s)
			}

			if fsutil.IsFile(path) {
				fd, err := os.Open(path)
				if err != nil {
					wt.Write(admErrStr(fmt.Sprintf("Failed to open log file: %s", err)))
				}
				defer fd.Close()
				r, err := gzip.NewReader(fd)
				if err != nil {
					wt.Write(admErrStr(fmt.Sprintf("Failed to create gzip reader: %s", err)))
				}
				defer r.Close()
				s := bufio.NewScanner(r)
				for s.Scan() {
					e := evtx.GoEvtxMap{}
					if err := json.Unmarshal(s.Bytes(), &e); err != nil {
						wt.Write(admErrStr("Incompatible parameters, specify either start/stop or pivot/delta parameters"))
					}
					if e.TimeCreated().After(start) && e.TimeCreated().Before(stop) {
						logs = append(logs, e)
					}
					// logs are ordered by time so if we go beyond stop, we can abort
					// main loop
					if e.TimeCreated().After(stop) {
						break Loop
					}
				}

				// we can close stuff in advance in case we have too many files to
				// iterate over, it would prevent to keep useless resources
				r.Close()
				fd.Close()

				if s.Err() != nil {
					wt.Write(admErrStr(fmt.Sprintf("Scanner terminated with error: %s", s.Err())))
				}
			}
			if s.After(stop) || s.After(time.Now()) {
				break
			}
		}
		wt.Write(NewAdminAPIResponse(logs).ToJSON())
	}
}

func (m *Manager) EndpointReport(wt http.ResponseWriter, rq *http.Request) {
	var euuid string
	var err error

	if euuid, err = muxGetVar(rq, "euuid"); err != nil {
		wt.Write(NewAdminAPIRespError(err).ToJSON())
	} else {
		if endpt, ok := m.endpoints.GetByUUID(euuid); ok {
			// we return the report anyway
			wt.Write(NewAdminAPIResponse(m.reducer.ReduceCopy(endpt.UUID)).ToJSON())
			// if request is DELETE we reset the report
			if rq.Method == "DELETE" {
				m.reducer.Delete(endpt.UUID)
			}
		} else {
			wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
		}
	}
}

func (m *Manager) EndpointsReports(wt http.ResponseWriter, rq *http.Request) {
	out := make(map[string]*reducer.ReducedStats)
	for _, e := range m.endpoints.MutEndpoints() {
		out[e.UUID] = m.reducer.ReduceCopy(e.UUID)
	}
	wt.Write(NewAdminAPIResponse(out).ToJSON())
}

func (m *Manager) runAdminAPI() {

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
		rt.Use(m.adminAuthorizationMiddleware)
		// Manages Compression
		rt.Use(gunzipMiddleware)

		// Routes initialization

		rt.HandleFunc(GetEndpointsURL, m.GetEndpoints).Methods("GET", "PUT")
		rt.HandleFunc(GetEndpointsByIdURL, m.GetEndpoint).Methods("GET", "DELETE")
		rt.HandleFunc(GetEndpointCommand, m.EndpointCommand).Methods("GET", "POST")
		rt.HandleFunc(GetEndpointCommandField, m.EndpointCommandField).Methods("GET")
		rt.HandleFunc(GetEndpointsReports, m.EndpointsReports).Methods("GET")
		rt.HandleFunc(GetEndpointLogs, m.EndpointLogs).Methods("GET")
		rt.HandleFunc(GetEndpointAlerts, m.EndpointLogs).Methods("GET")
		rt.HandleFunc(GetEndpointReport, m.EndpointReport).Methods("GET", "DELETE")

		uri := fmt.Sprintf("%s:%d", m.Config.AdminAPI.Host, m.Config.AdminAPI.Port)
		m.adminAPI = &http.Server{
			Handler:      rt,
			Addr:         uri,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		if m.Config.TLS.Empty() {
			// Bind to a port and pass our router in
			log.Infof("Running HTTP server on: %s", uri)
			if err := m.adminAPI.ListenAndServe(); err != http.ErrServerClosed {
				log.Panic(err)
			}
		} else {
			// Bind to a port and pass our router in
			log.Infof("Running HTTPS server on: %s", uri)
			if err := m.adminAPI.ListenAndServeTLS(m.Config.TLS.Cert, m.Config.TLS.Key); err != http.ErrServerClosed {
				log.Panic(err)
			}
		}
	}()
}
