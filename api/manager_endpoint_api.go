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

	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/gorilla/mux"
)

var (
	// ErrUnkEndpoint error to return when endpoint is unknown
	ErrUnkEndpoint = fmt.Errorf("unknown endpoint")
)

/////////////////// Utils

func (m *Manager) endpointFromRequest(rq *http.Request) *Endpoint {
	uuid := rq.Header.Get(EndpointUUIDHeader)
	if endpt, ok := m.endpoints.GetByUUID(uuid); ok {
		return endpt
	}
	return nil
}

func (m *Manager) mutEndpointFromRequest(rq *http.Request) *Endpoint {
	uuid := rq.Header.Get(EndpointUUIDHeader)
	if endpt, ok := m.endpoints.GetMutByUUID(uuid); ok {
		return endpt
	}
	return nil
}

// Middleware definitions

func (m *Manager) endpointAuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wt http.ResponseWriter, rq *http.Request) {
		var endpt *Endpoint
		var ok bool

		uuid := rq.Header.Get(EndpointUUIDHeader)
		key := rq.Header.Get(AuthKeyHeader)
		hostname := rq.Header.Get(EndpointHostnameHeader)
		ip := rq.Header.Get(EndpointIPHeader)

		if endpt, ok = m.endpoints.GetMutByUUID(uuid); !ok {
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}

		if endpt.Uuid != uuid || endpt.Key != key {
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}

		endpt.IP = ip

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

func endptLogHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// src-ip:src-port http-method http-proto url user-agent UUID content-length
		fmt.Printf("%s %s %s %s %s \"%s\" \"%s\" %d\n", time.Now().Format(time.RFC3339Nano), r.RemoteAddr, r.Method, r.Proto, r.URL, r.UserAgent(), r.Header.Get(EndpointUUIDHeader), r.ContentLength)
		next.ServeHTTP(w, r)
	})
}

func endptQuietLogHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isVerboseURL(r.URL) {
			// src-ip:src-port http-method http-proto url user-agent UUID content-length
			fmt.Printf("%s %s %s %s %s \"%s\" \"%s\" %d\n", time.Now().Format(time.RFC3339Nano), r.RemoteAddr, r.Method, r.Proto, r.URL, r.UserAgent(), r.Header.Get(EndpointUUIDHeader), r.ContentLength)
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
			rt.Use(endptLogHTTPMiddleware)
		} else {
			rt.Use(endptQuietLogHTTPMiddleware)
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
		rt.HandleFunc(EptAPIIoCsPath, m.IoCs).Methods("GET")
		rt.HandleFunc(EptAPIIoCsSha256Path, m.IoCsSha256).Methods("GET")

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
	wt.Write([]byte(m.gene.rules))
}

// RulesSha256 returns the sha256 of the latest set of rules loaded into the manager
func (m *Manager) RulesSha256(wt http.ResponseWriter, rq *http.Request) {
	m.RLock()
	defer m.RUnlock()
	wt.Write([]byte(m.gene.sha256))
}

func (m *Manager) IoCs(wt http.ResponseWriter, rq *http.Request) {
	if data, err := json.Marshal(m.iocs.StringSlice()); err != nil {
		log.Errorf("Failed to marshal IoCs: %s", err)
		http.Error(wt, "Failed to marshal IoCs", http.StatusInternalServerError)
	} else {
		wt.Write(data)
	}
}

func (m *Manager) IoCsSha256(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.iocs.Hash()))
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

		endptDumpDir := filepath.Join(m.Config.DumpDir, endpt.Uuid)
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

// Collect HTTP handler
func (m *Manager) Collect(wt http.ResponseWriter, rq *http.Request) {
	cnt := 0
	uuid := rq.Header.Get(EndpointUUIDHeader)

	defer rq.Body.Close()

	etid := m.eventLogger.InitTransaction()
	dtid := m.detectionLogger.InitTransaction()
	s := bufio.NewScanner(rq.Body)
	for s.Scan() {
		tok := []byte(s.Text())
		log.Debugf("Received Event: %s", string(tok))
		e := event.EdrEvent{}

		if err := json.Unmarshal(tok, &e); err != nil {
			log.Errorf("Failed to unmarshal: %s", tok)
		} else {

			// building up EdrData
			edrData := event.EdrData{}
			edrData.Event.Hash = utils.HashEventBytes(tok)
			edrData.Event.ReceiptTime = time.Now().UTC()

			edrData.Endpoint.UUID = uuid

			if endpt, ok := m.endpoints.GetMutByUUID(uuid); ok {
				edrData.Endpoint.IP = endpt.IP
				edrData.Endpoint.Hostname = endpt.Hostname
				edrData.Endpoint.Group = endpt.Group
			}
			edrData.Event.Detection = e.IsDetection()

			// setting EdrData
			e.Event.EdrData = &edrData

			if endpt := m.mutEndpointFromRequest(rq); endpt != nil {
				m.UpdateReducer(endpt.Uuid, &e)
				if e.IsDetection() {
					endpt.LastDetection = e.Timestamp()
				}
			} else {
				log.Error("Failed to retrieve endpoint from request")
			}

			// If it is an alert
			if e.IsDetection() {
				if _, err := m.detectionLogger.WriteEvent(dtid, uuid, &e); err != nil {
					log.Errorf("Failed to write detection: %s", err)
				}
			}

			if _, err := m.eventLogger.WriteEvent(etid, uuid, &e); err != nil {
				log.Errorf("Failed to write event: %s", err)
			}

			// we queue event for streaming
			m.eventStreamer.Queue(&e)
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
	id := rq.Header.Get(EndpointUUIDHeader)
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
