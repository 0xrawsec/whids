package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/mux"
)

var (
	// ErrUnkEndpoint error to return when endpoint is unknown
	ErrUnkEndpoint = fmt.Errorf("unknown endpoint")
)

/////////////////// Utils

func (m *Manager) endpointFromRequest(rq *http.Request) *Endpoint {
	uuid := rq.Header.Get("UUID")
	if endpt, ok := m.endpoints.GetByUUID(uuid); ok {
		return endpt
	}
	return nil
}

func (m *Manager) mutEndpointFromRequest(rq *http.Request) *Endpoint {
	uuid := rq.Header.Get("UUID")
	if endpt, ok := m.endpoints.GetMutByUUID(uuid); ok {
		return endpt
	}
	return nil
}

func (m *Manager) endpointAuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wt http.ResponseWriter, rq *http.Request) {
		var endpt *Endpoint
		var ok bool

		uuid := rq.Header.Get("UUID")
		key := rq.Header.Get("Api-Key")
		hostname := rq.Header.Get("Hostname")

		if endpt, ok = m.endpoints.GetMutByUUID(uuid); !ok {
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}

		if endpt.UUID != uuid || endpt.Key != key {
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}

		ip, err := IPFromRequest(rq)
		if err != nil {
			log.Errorf("Failed to parse client IP address: %s", err)
		} else {
			// update endpoint IP at every request if possible
			endpt.IP = ip.String()
		}

		switch {
		case endpt.Hostname == "":
			endpt.Hostname = hostname
		case endpt.Hostname != hostname:
			log.Errorf("Two hosts are using the same credentials %s (%s) and %s (%s)", endpt.Hostname, endpt.IP, hostname, ip)
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}

		// update last connection timestamp
		endpt.UpdateLastConnection()
		next.ServeHTTP(wt, rq)
	})
}

func isVerboseURL(u *url.URL) bool {
	for _, vu := range eptAPIVerbosePaths {
		if u.Path == vu {
			return true
		}
	}
	return false
}

func quietLogHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isVerboseURL(r.URL) {
			// src-ip:src-port http-method http-proto url user-agent UUID content-length
			fmt.Printf("%s %s %s %s %s \"%s\" \"%s\" %d\n", time.Now().Format(time.RFC3339Nano), r.RemoteAddr, r.Method, r.Proto, r.URL, r.UserAgent(), r.Header.Get("UUID"), r.ContentLength)
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) runEndpointAPI() {

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
		if m.Config.Logging.VerboseHTTP {
			rt.Use(logHTTPMiddleware)
		} else {
			rt.Use(quietLogHTTPMiddleware)
		}

		// Manages Authorization
		rt.Use(m.endpointAuthorizationMiddleware)
		// Manages Compression
		rt.Use(gunzipMiddleware)

		// Routes initialization
		// POST based
		rt.HandleFunc(EptAPIPostLogsPath, m.Collect).Methods("POST")
		rt.HandleFunc(EptAPIPostDumpPath, m.UploadDump).Methods("POST")

		// GET based
		rt.HandleFunc(EptAPIServerKeyPath, m.ServerKey).Methods("GET")
		rt.HandleFunc(EptAPIRulesPath, m.Rules).Methods("GET")
		rt.HandleFunc(EptAPIRulesSha256Path, m.RulesSha256).Methods("GET")
		rt.HandleFunc(EptAPIContainerPath, m.Container).Methods("GET")
		rt.HandleFunc(EptAPIContainerListPath, m.ContainerList).Methods("GET")
		rt.HandleFunc(EptAPIContainerSha256Path, m.ContainerSha256).Methods("GET")

		// GET and POST
		rt.HandleFunc(EptAPICommandPath, m.Command).Methods("GET", "POST")

		uri := fmt.Sprintf("%s:%d", m.Config.EndpointAPI.Host, m.Config.EndpointAPI.Port)
		m.endpointAPI = &http.Server{
			Handler:      rt,
			Addr:         uri,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		if m.Config.TLS.Empty() {
			// Bind to a port and pass our router in
			log.Infof("Running endpoint HTTP API server on: %s", uri)
			if err := m.endpointAPI.ListenAndServe(); err != http.ErrServerClosed {
				log.Panic(err)
			}
		} else {
			// Bind to a port and pass our router in
			log.Infof("Running endpoint HTTPS API server on: %s", uri)
			if err := m.endpointAPI.ListenAndServeTLS(m.Config.TLS.Cert, m.Config.TLS.Key); err != http.ErrServerClosed {
				log.Panic(err)
			}
		}
	}()
}

// ServerKey HTTP handler used to authenticate server on client side
func (m *Manager) ServerKey(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.Config.EndpointAPI.ServerKey))
}

// Rules HTTP handler used to serve the rules
func (m *Manager) Rules(wt http.ResponseWriter, rq *http.Request) {
	m.RLock()
	defer m.RUnlock()
	wt.Write([]byte(m.rules))
}

// RulesSha256 returns the sha256 of the latest set of rules loaded into the manager
func (m *Manager) RulesSha256(wt http.ResponseWriter, rq *http.Request) {
	m.RLock()
	defer m.RUnlock()
	wt.Write([]byte(m.rulesSha256))
}

// UploadDump HTTP handler used to upload dump files from client to manager
func (m *Manager) UploadDump(wt http.ResponseWriter, rq *http.Request) {
	defer rq.Body.Close()

	if m.Config.DumpDir == "" {
		log.Errorf("Upload handler won't dump because no dump directory set")
		http.Error(wt, "Failed to dump file", http.StatusInternalServerError)
		return
	}

	fu := FileUpload{}
	dec := json.NewDecoder(rq.Body)

	if endpt := m.endpointFromRequest(rq); endpt != nil {
		if err := dec.Decode(&fu); err != nil {
			log.Errorf("Upload handler failed to decode JSON")
			http.Error(wt, "Failed to decode JSON", http.StatusInternalServerError)
			return
		}

		endptDumpDir := filepath.Join(m.Config.DumpDir, endpt.UUID)
		if err := fu.Dump(endptDumpDir); err != nil {
			log.Errorf("Upload handler failed to dump file (%s): %s", fu.Implode(), err)
			http.Error(wt, "Failed to dump file", http.StatusInternalServerError)
			return
		}
	} else {
		log.Error("Failed to retrieve endpoint from request")
	}
}

// Container HTTP handler serves Gene containers to clients
func (m *Manager) Container(wt http.ResponseWriter, rq *http.Request) {
	m.RLock()
	defer m.RUnlock()
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
	m.RLock()
	defer m.RUnlock()
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
	m.RLock()
	defer m.RUnlock()
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
	uuid := rq.Header.Get("UUID")

	defer rq.Body.Close()

	etid := m.eventLogger.InitTransaction()
	dtid := m.detectionLogger.InitTransaction()
	s := bufio.NewScanner(rq.Body)
	for s.Scan() {
		tok := s.Text()
		log.Debugf("Received Event: %s", tok)
		e := evtx.GoEvtxMap{}
		if err := json.Unmarshal([]byte(tok), &e); err != nil {
			log.Errorf("Failed to unmarshal: %s", tok)
		} else {
			var isAlert bool

			// check if event is associated to an alert
			if _, err := e.Get(&sigPath); err == nil {
				isAlert = true
			}

			if endpt := m.mutEndpointFromRequest(rq); endpt != nil {
				m.UpdateReducer(endpt.UUID, &e)
				if isAlert {
					endpt.LastDetection = e.TimeCreated()
				}
			} else {
				log.Error("Failed to retrieve endpoint from request")
			}

			// If it is an alert
			if isAlert {
				if _, err := m.detectionLogger.WriteEvent(dtid, uuid, &e); err != nil {
					log.Errorf("Failed to write detection: %s", err)
				}
			}

			if _, err := m.eventLogger.WriteEvent(etid, uuid, &e); err != nil {
				log.Errorf("Failed to write event: %s", err)
			}
		}
		cnt++
	}

	if err := m.eventLogger.CommitTransaction(); err != nil {
		log.Errorf("Failed to commit event logger transaction: %s", err)
	}

	if err := m.detectionLogger.CommitTransaction(); err != nil {
		log.Errorf("Failed to commit detection logger transaction: %s", err)
	}
	log.Debugf("Count Event Received: %d", cnt)

}

// AddCommand sets a command to be executed on endpoint specified by UUID
func (m *Manager) AddCommand(uuid string, c *Command) error {
	if endpt, ok := m.endpoints.GetMutByUUID(uuid); ok {
		endpt.Command = c
		return nil
	}
	return ErrUnkEndpoint
}

// GetCommand gets the command set for an endpoint specified by UUID
func (m *Manager) GetCommand(uuid string) (*Command, error) {
	if endpt, ok := m.endpoints.GetByUUID(uuid); ok {
		// We return the command of an unmutable endpoint struct
		// so if Command is modified this will not affect Endpoint
		return endpt.Command, nil
	}
	return nil, ErrUnkEndpoint
}

// Command HTTP handler
func (m *Manager) Command(wt http.ResponseWriter, rq *http.Request) {
	id := rq.Header.Get("UUID")
	switch rq.Method {
	case "GET":
		if endpt, ok := m.endpoints.GetMutByUUID(id); ok {
			// we send back the command to execute only if was not already sent
			if endpt.Command != nil {
				if !endpt.Command.Sent {
					jsonCmd, err := json.Marshal(endpt.Command)
					if err != nil {
						log.Errorf("Failed at serializing command to JSON: %s", err)
					} else {
						wt.Write(jsonCmd)
					}
					endpt.Command.Sent = true
					endpt.Command.SentTime = time.Now()
					return
				}
			}
			// if the command is nil or already sent
			http.Error(wt, "", http.StatusNoContent)
		}
	case "POST":
		if endpt, ok := m.endpoints.GetMutByUUID(id); ok {
			// if command is nil we actually don't expect any result
			if endpt.Command != nil {
				if !endpt.Command.Completed {
					defer rq.Body.Close()
					body, err := ioutil.ReadAll(rq.Body)
					if err != nil {
						log.Errorf("Failed to read response body: %s", err)
					} else {
						rcmd := Command{}
						err := json.Unmarshal(body, &rcmd)
						if err != nil {
							log.Errorf("Failed to unmarshal received command: %s", err)
						} else {
							// we complete the command executed on the endpoint
							endpt.Command.Complete(&rcmd)
						}
					}
				} else {
					log.Errorf("Command is already completed")
				}
			}
		}
	}
}
