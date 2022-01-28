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
	"github.com/0xrawsec/whids/hids/sysinfo"
	"github.com/0xrawsec/whids/utils"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/gorilla/mux"
)

var (
	// ErrUnkEndpoint error to return when endpoint is unknown
	ErrUnkEndpoint = fmt.Errorf("unknown endpoint")
)

/////////////////// Utils

func (m *Manager) eptAPIMutEndpointFromRequest(rq *http.Request) *Endpoint {
	uuid := rq.Header.Get(EndpointUUIDHeader)
	if endpt, ok := m.MutEndpoint(uuid); ok {
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

		if endpt, ok = m.MutEndpoint(uuid); !ok {
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
			m.logAPIErrorf("two hosts are using the same credentials %s (%s) and %s (%s)", endpt.Hostname, endpt.IP, hostname, ip)
			http.Error(wt, "Not Authorized", http.StatusForbidden)
			// we have to return not to reach ServeHTTP
			return
		}

		// update last connection timestamp
		endpt.UpdateLastConnection()
		if err := m.db.InsertOrUpdate(endpt); err != nil {
			m.logAPIErrorf("failed to commit endpoint changes")
		}
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
		rt.HandleFunc(EptAPIPostLogsPath, m.eptAPICollect).Methods("POST")
		rt.HandleFunc(EptAPIPostDumpPath, m.eptAPIUploadDump).Methods("POST")
		rt.HandleFunc(EptAPIPostSystemInfo, m.eptAPISystemInfo).Methods("POST")

		// GET based
		rt.HandleFunc(EptAPIServerKeyPath, m.eptAPIServerKey).Methods("GET")
		rt.HandleFunc(EptAPIRulesPath, m.eptAPIRules).Methods("GET")
		rt.HandleFunc(EptAPIRulesSha256Path, m.eptAPIRulesSha256).Methods("GET")
		rt.HandleFunc(EptAPIIoCsPath, m.eptAPIIoCs).Methods("GET")
		rt.HandleFunc(EptAPIIoCsSha256Path, m.eptAPIIoCsSha256).Methods("GET")

		// GET and POST
		rt.HandleFunc(EptAPICommandPath, m.eptAPICommand).Methods("GET", "POST")

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

// eptAPIServerKey HTTP handler used to authenticate server on client side
func (m *Manager) eptAPIServerKey(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.Config.EndpointAPI.ServerKey))
}

// eptAPIRules HTTP handler used to serve the rules
func (m *Manager) eptAPIRules(wt http.ResponseWriter, rq *http.Request) {
	m.RLock()
	defer m.RUnlock()
	wt.Write([]byte(m.gene.rules))
}

// eptAPIRulesSha256 returns the sha256 of the latest set of rules loaded into the manager
func (m *Manager) eptAPIRulesSha256(wt http.ResponseWriter, rq *http.Request) {
	m.RLock()
	defer m.RUnlock()
	wt.Write([]byte(m.gene.sha256))
}

func (m *Manager) eptAPIIoCs(wt http.ResponseWriter, rq *http.Request) {
	if data, err := json.Marshal(m.iocs.StringSlice()); err != nil {
		m.logAPIErrorf("failed to marshal IoCs: %s", err)
		http.Error(wt, "Failed to marshal IoCs", http.StatusInternalServerError)
	} else {
		wt.Write(data)
	}
}

func (m *Manager) eptAPIIoCsSha256(wt http.ResponseWriter, rq *http.Request) {
	wt.Write([]byte(m.iocs.Hash()))
}

// eptAPIUploadDump HTTP handler used to upload dump files from client to manager
func (m *Manager) eptAPIUploadDump(wt http.ResponseWriter, rq *http.Request) {
	defer rq.Body.Close()

	if m.Config.DumpDir == "" {
		m.logAPIErrorf("handler won't dump because no dump directory set")
		http.Error(wt, "Failed to dump file", http.StatusInternalServerError)
		return
	}

	fu := FileUpload{}
	dec := json.NewDecoder(rq.Body)

	if endpt := m.eptAPIMutEndpointFromRequest(rq); endpt != nil {
		if err := dec.Decode(&fu); err != nil {
			m.logAPIErrorf("handler failed to decode JSON")
			http.Error(wt, "Failed to decode JSON", http.StatusInternalServerError)
			return
		}

		endptDumpDir := filepath.Join(m.Config.DumpDir, endpt.Uuid)
		if err := fu.Dump(endptDumpDir); err != nil {
			m.logAPIErrorf("handler failed to dump file (%s): %s", fu.Implode(), err)
			http.Error(wt, "Failed to dump file", http.StatusInternalServerError)
			return
		}
	} else {
		m.logAPIErrorf("failed to retrieve endpoint from request")
	}
}

// Container HTTP handler serves Gene containers to clients

// eptAPICollect HTTP handler
func (m *Manager) eptAPICollect(wt http.ResponseWriter, rq *http.Request) {
	defer rq.Body.Close()

	funcName := utils.GetCurFuncName()
	cnt := 0
	uuid := rq.Header.Get(EndpointUUIDHeader)
	endpt, _ := m.MutEndpoint(uuid)

	etid := m.eventLogger.InitTransaction()
	dtid := m.detectionLogger.InitTransaction()
	s := bufio.NewScanner(rq.Body)
	for s.Scan() {
		tok := []byte(s.Text())
		log.Debugf("%s received Event: %s", funcName, string(tok))
		e := event.EdrEvent{}

		if err := json.Unmarshal(tok, &e); err != nil {
			m.logAPIErrorf("failed to unmarshal: %s", tok)
		} else {

			// building up EdrData
			edrData := event.EdrData{}
			edrData.Event.Hash = utils.HashEventBytes(tok)
			edrData.Event.ReceiptTime = time.Now().UTC()

			edrData.Endpoint.UUID = uuid
			if endpt != nil {
				// updating EdrData fields
				edrData.Endpoint.IP = endpt.IP
				edrData.Endpoint.Hostname = endpt.Hostname
				edrData.Endpoint.Group = endpt.Group

				// updating reducer
				m.UpdateReducer(endpt.Uuid, &e)

				// updating last detection
				if e.IsDetection() {
					endpt.LastDetection = e.Timestamp()
				}
			}

			edrData.Event.Detection = e.IsDetection()

			// setting EdrData
			e.Event.EdrData = &edrData

			// If it is an alert
			if e.IsDetection() {
				if _, err := m.detectionLogger.WriteEvent(dtid, uuid, &e); err != nil {
					m.logAPIErrorf("failed to write detection: %s", err)
				}
			}

			if _, err := m.eventLogger.WriteEvent(etid, uuid, &e); err != nil {
				m.logAPIErrorf("failed to write event: %s", err)
			}

			// we queue event for streaming
			m.eventStreamer.Queue(&e)
		}
		cnt++
	}

	if endpt != nil {
		if err := m.db.InsertOrUpdate(endpt); err != nil {
			m.logAPIErrorf("failed to update endpoint UUID=%s: %s", endpt.Uuid, err)
		}
	}

	if err := m.eventLogger.CommitTransaction(); err != nil {
		m.logAPIErrorf("failed to commit event logger transaction: %s", err)
	}

	if err := m.detectionLogger.CommitTransaction(); err != nil {
		m.logAPIErrorf("failed to commit detection logger transaction: %s", err)
	}
	log.Debugf("count Event Received: %d", cnt)

}

// eptAPICommand HTTP handler
func (m *Manager) eptAPICommand(wt http.ResponseWriter, rq *http.Request) {

	switch rq.Method {
	case "GET":
		if endpt := m.eptAPIMutEndpointFromRequest(rq); endpt != nil {
			// we send back the command to execute only if was not already sent
			if endpt.Command != nil {
				if !endpt.Command.Sent {
					jsonCmd, err := json.Marshal(endpt.Command)
					if err != nil {
						m.logAPIErrorf("failed at serializing command to JSON: %s", err)
					} else {
						wt.Write(jsonCmd)
					}
					endpt.Command.Sent = true
					endpt.Command.SentTime = time.Now()
					if err := m.db.InsertOrUpdate(endpt); err != nil {
						m.logAPIErrorf("failed to update endpoint data: %s", err)
					}
					return
				}
			}
			// if the command is nil or already sent
			http.Error(wt, "", http.StatusNoContent)
		}
	case "POST":
		if endpt := m.eptAPIMutEndpointFromRequest(rq); endpt != nil {
			// if command is nil we actually don't expect any result
			if endpt.Command != nil {
				if !endpt.Command.Completed {
					defer rq.Body.Close()
					body, err := ioutil.ReadAll(rq.Body)
					if err != nil {
						m.logAPIErrorf("failed to read response body: %s", err)
					} else {
						rcmd := Command{}
						err := json.Unmarshal(body, &rcmd)
						if err != nil {
							m.logAPIErrorf("failed to unmarshal received command: %s", err)
						} else {
							// we complete the command executed on the endpoint
							endpt.Command.Complete(&rcmd)
							if err := m.db.InsertOrUpdate(endpt); err != nil {
								m.logAPIErrorf("to update endpoint data: %s", err)
							}
						}
					}
				} else {
					m.logAPIErrorf("command is already completed")
				}
			}
		}
	}
}

// Command HTTP handler
func (m *Manager) eptAPISystemInfo(wt http.ResponseWriter, rq *http.Request) {
	switch rq.Method {
	case "POST":
		if endpt := m.eptAPIMutEndpointFromRequest(rq); endpt != nil {
			info := sysinfo.SystemInfo{}
			if err := readPostAsJSON(rq, &info); err != nil {
				m.logAPIErrorf("failed to receive system information for %s", endpt.Uuid)
				http.Error(wt, "Failed to unmarshal data", http.StatusInternalServerError)
			} else {
				endpt.SystemInfo = &info
				m.db.InsertOrUpdate(endpt)
				if err := m.db.InsertOrUpdate(endpt); err != nil {
					m.logAPIErrorf("to update endpoint data: %s", err)
				}
			}
		}
	}
}
