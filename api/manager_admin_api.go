package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/gene/reducer"
	"github.com/0xrawsec/gene/rules"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/gorilla/websocket"

	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/mux"
)

const (
	MaxLimitLogAPI = 10000
)

func admApiParseTime(stimestamp string) (t time.Time, err error) {
	if t, err = time.Parse(time.RFC3339, stimestamp); err != nil {
		return
	}
	return
}

func muxGetVar(rq *http.Request, name string) (string, error) {
	vars := mux.Vars(rq)
	if value, ok := vars[name]; ok {
		return value, nil
	}
	return "", fmt.Errorf("unknown mux variable")
}

func format(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// read posted data and unseriablize it from JSON
func readPostAsJSON(rq *http.Request, i interface{}) error {
	defer rq.Body.Close()
	b, err := ioutil.ReadAll(rq.Body)
	if err != nil {
		return fmt.Errorf("failed to read POST body: %w", err)
	}
	return json.Unmarshal(b, i)
}

// AdminAPIConfig configuration for Administrative API
type AdminAPIConfig struct {
	Host  string      `toml:"host" comment:"Hostname or IP address where the API should listen to"`
	Port  int         `toml:"port" comment:"Port used by the API"`
	Users []AdminUser `toml:"users" comment:"List of admin users"`
}

//////////////// AdminAPIResponse

// AdminAPIResponse standard structure to encode any response
// from the AdminAPI
type AdminAPIResponse struct {
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
	Error   string      `json:"error"`
}

// NewAdminAPIResponse creates a new response from data
func NewAdminAPIResponse(data interface{}) *AdminAPIResponse {
	return &AdminAPIResponse{Data: data, Message: "OK"}
}

// NewAdminAPIRespError creates a new response from an error
func NewAdminAPIRespError(err error) *AdminAPIResponse {
	return &AdminAPIResponse{Message: "NOK", Error: format("%s", err)}
}

// NewAdminAPIRespErrorString creates a new error response from an error
func NewAdminAPIRespErrorString(err string) *AdminAPIResponse {
	return &AdminAPIResponse{Message: "NOK", Error: err}
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
		safe := AdminAPIResponse{Error: format("Failed to encode data to JSON: %s", err)}
		sb, _ := json.Marshal(safe)
		return sb
	}
	return b
}

func admErrStr(s string) []byte {
	return NewAdminAPIRespErrorString(s).ToJSON()
}

func admJSONResp(data interface{}) []byte {
	return NewAdminAPIResponse(data).ToJSON()
}

func admMsgStr(s string) []byte {
	r := AdminAPIResponse{Message: s}
	return r.ToJSON()
}

/////////////////// Manager functions

var (
	upgrader = websocket.Upgrader{} // use default options
)

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

func (m *Manager) admAPIEndpoints(wt http.ResponseWriter, rq *http.Request) {
	showKey, _ := strconv.ParseBool(rq.URL.Query().Get("showkey"))
	switch {
	case rq.Method == "GET":
		// we return the list of all endpoints
		endpoints := make([]*Endpoint, 0, m.endpoints.Len())
		for _, endpt := range m.endpoints.Endpoints() {
			// never show command
			endpt.Command = nil
			if !showKey {
				endpt.Key = ""
			}
			// score is updated at every call as it depends on all the other endpoints
			endpt.Score = m.reducer.Score(endpt.UUID)
			// add endpoint to the list to return
			endpoints = append(endpoints, endpt)
		}
		wt.Write(NewAdminAPIResponse(endpoints).ToJSON())

	case rq.Method == "PUT":
		endpt := NewEndpoint(UUIDGen().String(), KeyGen(DefaultKeySize))
		m.endpoints.Add(endpt)
		m.Config.AddEndpointConfig(endpt.UUID, endpt.Key)
		if err := m.Config.Save(); err != nil {
			log.Errorf("GetNewEndpoint failed to save config: %s", err)
		}
		wt.Write(NewAdminAPIResponse(endpt).ToJSON())
	}
}

func (m *Manager) admAPIEndpoint(wt http.ResponseWriter, rq *http.Request) {
	var euuid string
	var err error

	showKey, _ := strconv.ParseBool(rq.URL.Query().Get("showkey"))

	if euuid, err = muxGetVar(rq, "euuid"); err == nil {
		if endpt, ok := m.endpoints.GetByUUID(euuid); ok {
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
			if !showKey {
				endpt.Key = ""
			}
			// score is updated at every call as it depends on all the other endpoints
			endpt.Score = m.reducer.Score(endpt.UUID)
			wt.Write(NewAdminAPIResponse(endpt).ToJSON())
		} else {
			wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
		}
	} else {
		wt.Write(admErrStr(format("Failed to parse URL: %s", err)))
	}
}

// CommandAPI structure used by Admin API clients to POST commands
type CommandAPI struct {
	CommandLine string        `json:"command-line"`
	FetchFiles  []string      `json:"fetch-files"`
	DropFiles   []string      `json:"drop-files"`
	Timeout     time.Duration `json:"timeout"`
}

// ToCommand converts a CommandAPI to a Command
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

func (m *Manager) admAPIEndpointCommand(wt http.ResponseWriter, rq *http.Request) {
	var euuid string
	var err error

	switch rq.Method {
	case "GET":
		wait, _ := strconv.ParseBool(rq.URL.Query().Get("wait"))
		if euuid, err = muxGetVar(rq, "euuid"); err != nil {
			wt.Write(NewAdminAPIRespError(err).ToJSON())
		} else {
			if endpt, ok := m.endpoints.GetByUUID(euuid); ok {
				if endpt.Command != nil {
					for wait && !endpt.Command.Completed {
						time.Sleep(time.Millisecond * 50)
					}
				}
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

func (m *Manager) admAPIEndpointCommandField(wt http.ResponseWriter, rq *http.Request) {
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
					case "files", "fetch":
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

func (m *Manager) admAPIEndpointLogs(wt http.ResponseWriter, rq *http.Request) {
	var err error
	var euuid string
	var start, stop, pivot time.Time
	var last, delta time.Duration
	var skip int64

	// default limit
	limit := 1000

	logs := make([]evtx.GoEvtxMap, 0)
	pStart := rq.URL.Query().Get("start")
	pStop := rq.URL.Query().Get("stop")
	pLast := rq.URL.Query().Get("last")

	pPivot := rq.URL.Query().Get("pivot")
	pDelta := rq.URL.Query().Get("delta")

	pLimit := rq.URL.Query().Get("limit")
	pSkip := rq.URL.Query().Get("skip")

	now := time.Now()

	// Parsing parameters
	if pStart != "" {
		if start, err = admApiParseTime(pStart); err != nil {
			wt.Write(admErrStr("Failed to parse start parameter, it must be RFC3339 formated"))
			return
		}
	}

	if pStop != "" {
		if stop, err = admApiParseTime(pStop); err != nil {
			wt.Write(admErrStr("Failed to parse stop parameter, it must be RFC3339 formated"))
			return
		}
	}

	if pLast != "" {
		if last, err = time.ParseDuration(pLast); err != nil {
			if n, err := fmt.Sscanf(pLast, "%dd", &last); n != 1 || err != nil {
				log.Infof("n=%d err=%s", n, err)
				wt.Write(admErrStr("Failed to parse last parameter, it must be a valid Go time.Duration format"))
				return
			}
			last *= 24 * time.Hour
		}
	}

	if pPivot != "" {
		if pivot, err = admApiParseTime(pPivot); err != nil {
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

	if pSkip != "" {
		if skip, err = strconv.ParseInt(pSkip, 10, 64); err != nil {
			wt.Write(admErrStr(format("Failed to parse skip parameter: %s", err)))
			return
		}
	}

	if pLimit != "" {
		// we don't raise error here on bad conversion
		if l, err := strconv.Atoi(pLimit); err == nil {
			if l <= MaxLimitLogAPI {
				limit = l
			} else {
				limit = MaxLimitLogAPI
			}
		}
	}

	// Default settings last hour
	if pStart == "" && pStop == "" && pPivot == "" && pDelta == "" && pLast == "" {
		last = time.Hour
	}

	// Using last parameter
	if last != 0 {
		start = now.Add(-last)
		stop = now
		goto searchLogs
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

	if !start.IsZero() && stop.IsZero() {
		stop = now
	}

searchLogs:
	// Controlling parameters
	if start.After(stop) {
		wt.Write(admErrStr("Start date must be before stop date"))
		return
	}
	if euuid, err = muxGetVar(rq, "euuid"); err != nil {
		wt.Write(NewAdminAPIRespError(err).ToJSON())
	} else {
		searcher := m.eventSearcher

		if strings.HasSuffix(rq.URL.Path, AdmAPIDetectionPart) {
			searcher = m.detectionSearcher
		}

		for rawEvent := range searcher.Events(start, stop, euuid, int(limit), int(skip)) {
			if e, err := rawEvent.Event(); err != nil {
				log.Errorf("Failed to encode event to JSON: %s", err)
			} else {
				logs = append(logs, e)
			}
		}

		// we had an issue doing the search
		if searcher.Err() != nil {
			wt.Write(admErrStr(format("failed to search events: %s", searcher.Err())))
			return
		}

		wt.Write(NewAdminAPIResponse(logs).ToJSON())
	}
}

func (m *Manager) admAPIEndpointReport(wt http.ResponseWriter, rq *http.Request) {
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

func (m *Manager) admAPIEndpointsReports(wt http.ResponseWriter, rq *http.Request) {
	out := make(map[string]*reducer.ReducedStats)
	for _, e := range m.endpoints.MutEndpoints() {
		out[e.UUID] = m.reducer.ReduceCopy(e.UUID)
	}
	wt.Write(NewAdminAPIResponse(out).ToJSON())
}

type EndpointDumps struct {
	UpdateTimestamp time.Time `json:"update"`
	ProcessGUID     string    `json:"process-guid"`
	EventHash       string    `json:"event-hash"`
	BaseURL         string    `json:"base-url"`
	Files           []string  `json:"files"`
}

func listEndpointDumps(root, uuid string, since time.Time) (dumps []EndpointDumps, err error) {
	var procGUIDs, eventHashes, eventDumps []fs.DirEntry

	dumps = make([]EndpointDumps, 0)
	urlPath := fmt.Sprintf("%s/%s%s", AdmAPIEndpointsPath, uuid, admAPIArtifactsPart)

	path := filepath.Join(root, uuid)
	if procGUIDs, err = os.ReadDir(path); err != nil {
		return
	}

	for _, pfi := range procGUIDs {
		if pfi.IsDir() {
			evtHashDir := filepath.Join(path, pfi.Name())
			if eventHashes, err = os.ReadDir(evtHashDir); err != nil {
				err = fmt.Errorf("failed to list (event hash) directory: %s", err)
				return
			}

			for _, efi := range eventHashes {
				// we remove the curly brackets of the process GUID as gorilla
				// has issue handling those. Important for API retrieving dump file
				pguid := strings.Trim(pfi.Name(), "{}")
				ehash := efi.Name()
				baseURL := format("%s/%s/%s/", urlPath, pguid, ehash)
				ed := EndpointDumps{ProcessGUID: pguid, EventHash: ehash, BaseURL: baseURL, Files: make([]string, 0)}
				if efi.IsDir() {
					evtDumpDir := filepath.Join(evtHashDir, ehash)
					if eventDumps, err = os.ReadDir(evtDumpDir); err != nil {
						err = fmt.Errorf("failed to list (event dump) directory: %s", err)
						return
					}

					for _, dfi := range eventDumps {
						var info fs.FileInfo
						if info, err = dfi.Info(); err != nil {
							err = fmt.Errorf("failed to read file (%s) info: %s", filepath.Join(evtDumpDir, dfi.Name()), err)
							return
						}
						// we add file to the list of files only if it has
						// been modified after the since parameter
						if since.Before(info.ModTime()) {
							ed.Files = append(ed.Files, dfi.Name())
						}
						if ed.UpdateTimestamp.Before(info.ModTime()) {
							ed.UpdateTimestamp = info.ModTime().UTC()
						}
					}
				}
				// we don't update if update timestamp is before since parameter
				if since.Before(ed.UpdateTimestamp) {
					dumps = append(dumps, ed)
				}
			}
		}
	}
	return

}

func (m *Manager) admAPIArtifacts(wt http.ResponseWriter, rq *http.Request) {
	var err error
	var since time.Time
	var uuids []fs.DirEntry

	pSince := rq.URL.Query().Get("since")
	resp := make(map[string][]EndpointDumps)

	if pSince != "" {
		if since, err = admApiParseTime(pSince); err != nil {
			wt.Write(admErrStr(format("Failed to parse since parameter: %s", err)))
			return
		}
	}

	if uuids, err = os.ReadDir(m.Config.DumpDir); err != nil {
		wt.Write(admErrStr(format("Failed to read dump directory: %s", err)))
		return
	}

	for _, uuid := range uuids {
		if uuid.IsDir() {
			if resp[uuid.Name()], err = listEndpointDumps(m.Config.DumpDir, uuid.Name(), since); err != nil {
				wt.Write(admErrStr(format("Failed list dumps for uuid=%s , %s", uuid.Name(), err)))
				return
			}
		}
	}
	wt.Write(admJSONResp(resp))
}

func (m *Manager) admAPIEndpointArtifacts(wt http.ResponseWriter, rq *http.Request) {
	var euuid string
	var err error
	var since time.Time
	var dumps []EndpointDumps

	pSince := rq.URL.Query().Get("since")

	if pSince != "" {
		if since, err = admApiParseTime(pSince); err != nil {
			wt.Write(admErrStr(format("Failed to parse since parameter: %s", err)))
			return
		}
	}

	if euuid, err = muxGetVar(rq, "euuid"); err != nil {
		wt.Write(NewAdminAPIRespError(err).ToJSON())
	} else {
		if m.endpoints.HasByUUID(euuid) {
			if dumps, err = listEndpointDumps(m.Config.DumpDir, euuid, since); err != nil {
				wt.Write(admErrStr(format("Failed to list dumps, %s", err)))
				return
			}
			wt.Write(admJSONResp(dumps))
			return
		} else {
			wt.Write(admErrStr(format("Unknown endpoint: %s", euuid)))
		}
	}
}

func (m *Manager) admAPIEndpointArtifact(wt http.ResponseWriter, rq *http.Request) {

	raw, _ := strconv.ParseBool(rq.URL.Query().Get("raw"))
	gunzip, _ := strconv.ParseBool(rq.URL.Query().Get("gunzip"))

	if euuid, err := muxGetVar(rq, "euuid"); err == nil {
		if pguid, err := muxGetVar(rq, "pguid"); err == nil {
			if ehash, err := muxGetVar(rq, "ehash"); err == nil {
				if fname, err := muxGetVar(rq, "fname"); err == nil {
					// sanitize pguid
					pguid = format("{%s}", strings.Trim(pguid, "{}"))
					dumpDir := filepath.Join(m.Config.DumpDir, euuid, pguid, ehash)
					if dumpFiles, err := ioutil.ReadDir(dumpDir); err == nil {
						for _, dfi := range dumpFiles {
							exists := filepath.Join(dumpDir, dfi.Name())
							fetch := filepath.Join(dumpDir, fname)
							if exists == fetch {
								var r io.ReadCloser
								if fd, err := os.Open(fetch); err == nil {
									r = fd
									if gunzip {
										if r, err = gzip.NewReader(fd); err != nil {
											wt.Write(admErrStr(format("Failed to gunzip file: %s", err)))
											return
										}
									}

									// defer closing of the reader
									defer r.Close()

									if data, err := ioutil.ReadAll(r); err == nil {
										// if we want the raw file
										if raw {
											wt.Write(data)
										} else {
											wt.Write(admJSONResp(data))
										}
									} else {
										wt.Write(admErrStr(format("Cannot read file: %s", err)))
									}
								} else {
									wt.Write(admErrStr(format("Cannot open file: %s", err)))
								}
								// we have to return here as we successed or failed to read file
								return
							}
						}
						wt.Write(admErrStr("File not found"))
					} else {
						wt.Write(admErrStr(format("Failed at listing dump directory: %s", err)))
					}
				} else {
					wt.Write(admErrStr(err.Error()))
				}
			} else {
				wt.Write(admErrStr(err.Error()))
			}
		} else {
			wt.Write(admErrStr(err.Error()))
		}
	} else {
		wt.Write(admErrStr(err.Error()))
	}
}

type stats struct {
	EndpointCount int `json:"endpoint-count"`
	RuleCount     int `json:"rule-count"`
}

func (m *Manager) admAPIStats(wt http.ResponseWriter, rq *http.Request) {
	s := stats{
		EndpointCount: m.endpoints.Len(),
		RuleCount:     m.geneEng.Count(),
	}
	wt.Write(NewAdminAPIResponse(s).ToJSON())
}

func (m *Manager) admAPIRules(wt http.ResponseWriter, rq *http.Request) {
	// used in case of POST / DELETE
	rulesBasename := "compiled-updated.gen"
	name := rq.URL.Query().Get("name")
	filters, _ := strconv.ParseBool(rq.URL.Query().Get("filters"))

	switch rq.Method {
	case "GET":
		rulesList := make([]rules.Rule, 0, m.geneEng.Count())
		if name == "" {
			name = ".*"
		}
		for r := range m.geneEng.GetRawRule(name) {
			jr := rules.Rule{}
			if err := json.Unmarshal([]byte(r), &jr); err != nil {
				wt.Write(admErrStr(err.Error()))
				return
			}
			// we continue if we want filters and rule is not a filter
			if filters && !jr.Meta.Filter {
				continue
			}
			rulesList = append(rulesList, jr)
		}
		wt.Write(NewAdminAPIResponse(rulesList).ToJSON())

	case "DELETE":
		// we want to be sure to be able to create the file before going on
		newRulesPath := filepath.Join(m.Config.RulesDir, rulesBasename)
		if m.geneEng.GetRawRuleByName(name) == "" {
			wt.Write(admErrStr(format(`No such rule "%s", doing nothing`, name)))
			return
		}

		fd, err := os.Create(format("%s.tmp", newRulesPath))
		if err != nil {
			wt.Write(admErrStr(format("Cannot create temporary file: %s", err)))
			return
		}
		defer fd.Close()

		// we delete previous rule files
		for wi := range fswalker.Walk(m.Config.RulesDir) {
			for _, fi := range wi.Files {
				fp := filepath.Join(m.Config.RulesDir, fi.Name())
				if engine.DefaultRuleExtensions.Contains(filepath.Ext(fp)) {
					if err := os.Remove(fp); err != nil {
						wt.Write(admErrStr(format("Failed to delete rule file: %s", err)))
						return
					}
				}
			}
		}

		// we update the rule file
		for _, ruleName := range m.geneEng.GetRuleNames() {
			if name != ruleName {
				// we write as is the rules not needing updates
				if _, err := fd.WriteString(format("%s\n", m.geneEng.GetRawRuleByName(ruleName))); err != nil {
					wt.Write(admErrStr(format("Failed to write rule, updated rule file only contain partial results, a manual fix is required: %s", err)))
					return
				}
			}
		}

		// close file before renaming
		fd.Close()
		if err := os.Rename(format("%s.tmp", newRulesPath), newRulesPath); err != nil {
			wt.Write(admErrStr(format("Failed to rename temporary rule file, you must rename it manually: %s", err)))
			return
		}
		wt.Write(admMsgStr("Rules updated succesfully, engine needs to be reloaded"))

	case "POST":
		m.Lock()
		defer m.Unlock()
		defer rq.Body.Close()
		paramUpdate := rq.URL.Query().Get("update")
		b, err := ioutil.ReadAll(rq.Body)
		if err != nil {
			wt.Write(admErrStr(format("Failed to read request body: %s", err)))
		} else {
			// LoadReader also asses that the rules are all compilable
			if err := m.geneEng.LoadReader(bytes.NewReader(b)); err != nil {
				update, _ := strconv.ParseBool(paramUpdate)
				// if we have the correct error and we want to replace existing rules
				if _, ok := err.(engine.ErrRuleExist); ok && update {
					// we want to be sure to be able to create the file before going on
					newRulesPath := filepath.Join(m.Config.RulesDir, rulesBasename)
					fd, err := os.Create(format("%s.tmp", newRulesPath))
					if err != nil {
						wt.Write(admErrStr(format("Cannot create temporary file: %s", err)))
						return
					}
					defer fd.Close()

					// we verify we can decode all the body
					newRules := make(map[string]rules.Rule)
					dec := json.NewDecoder(bytes.NewReader(b))
					for {
						jr := rules.Rule{}
						err := dec.Decode(&jr)

						if err == io.EOF {
							break
						}
						if err != nil {
							wt.Write(admErrStr(format("Failed to parse body content as JSON: %s", err)))
							return
						}
						newRules[jr.Name] = jr
					}

					// we delete previous rule files
					for wi := range fswalker.Walk(m.Config.RulesDir) {
						for _, fi := range wi.Files {
							fp := filepath.Join(m.Config.RulesDir, fi.Name())
							if engine.DefaultRuleExtensions.Contains(filepath.Ext(fp)) {
								if err := os.Remove(fp); err != nil {
									wt.Write(admErrStr(format("Failed to delete rule file: %s", err)))
									return
								}
							}
						}
					}

					// we update the rule file
					for _, name := range m.geneEng.GetRuleNames() {
						// we write as is the rules not needing updates
						if _, ok := newRules[name]; !ok {
							if _, err := fd.WriteString(format("%s\n", m.geneEng.GetRawRuleByName(name))); err != nil {
								wt.Write(admErrStr(format("Fail to write rule, new rule file only contain partial results, a manual fix is required: %s", err)))
								return
							}
						}
					}
					for _, rule := range newRules {
						json, _ := rule.JSON()
						if _, err := fd.WriteString(format("%s\n", json)); err != nil {
							wt.Write(admErrStr(format("Fail to write rule, new rule file only contain partial results, a manual fix is required: %s", err)))
							return
						}
					}
					// close file before renaming
					fd.Close()
					if err := os.Rename(format("%s.tmp", newRulesPath), newRulesPath); err != nil {
						wt.Write(admErrStr(format("Fail to rename temporary rule file, you must rename it manually: %s", err)))
						return
					}
					wt.Write(admMsgStr("Rules updated succesfully, engine needs to be reloaded"))
				} else {
					// we return an error because we don't want to replace existing rules
					wt.Write(admErrStr(format("Error loading rule: %s", err)))
				}
			} else {
				wt.Write(admMsgStr("Rules added successfully, please save rules for persistence"))
			}
		}
	}
}

func (m *Manager) admAPIRulesReload(wt http.ResponseWriter, rq *http.Request) {
	m.Lock()
	defer m.Unlock()
	// Gene engine initialization
	if err := m.LoadGeneEngine(); err != nil {
		wt.Write(admErrStr(format("Failed to reload engine: %s", err)))
	} else {
		// Gene Reducer initialization (used to generate reports)
		m.reducer = reducer.NewReducer(m.geneEng)
	}
	m.admAPIStats(wt, rq)
}

func (m *Manager) admAPIRulesSave(wt http.ResponseWriter, rq *http.Request) {
	rulesBasename := "compiled-updated.gen"
	newRulesPath := filepath.Join(m.Config.RulesDir, rulesBasename)

	// we want to be sure to be able to create the file before going on
	fd, err := os.Create(format("%s.tmp", newRulesPath))
	if err != nil {
		wt.Write(admErrStr(format("Cannot create temporary file: %s", err)))
		return
	}

	// we delete previous rule files
	for wi := range fswalker.Walk(m.Config.RulesDir) {
		for _, fi := range wi.Files {
			fp := filepath.Join(m.Config.RulesDir, fi.Name())
			if engine.DefaultRuleExtensions.Contains(filepath.Ext(fp)) {
				if err := os.Remove(fp); err != nil {
					wt.Write(admErrStr(format("Failed to delete rule file: %s", err)))
					return
				}
			}
		}
	}

	// we update the rule file
	for _, ruleName := range m.geneEng.GetRuleNames() {
		// we write as is the rules not needing updates
		if _, err := fd.WriteString(format("%s\n", m.geneEng.GetRawRuleByName(ruleName))); err != nil {
			wt.Write(admErrStr(format("Failed to write rule, updated rule file only contain partial results, a manual fix is required: %s", err)))
			return
		}
	}

	// close file before renaming
	fd.Close()
	if err := os.Rename(format("%s.tmp", newRulesPath), newRulesPath); err != nil {
		wt.Write(admErrStr(format("Failed to rename temporary rule file, you must rename it manually: %s", err)))
		return
	}
	wt.Write(admMsgStr("Rules saved succesfully on disk"))
	defer fd.Close()
}

func wsHandleControlMessage(c *websocket.Conn) {
	for {
		if _, _, err := c.NextReader(); err != nil {
			c.Close()
			break
		}
	}
}

func (m *Manager) admAPIStreamEvents(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("StreamLogs, failed to upgrade to websocket: %s", err)
		return
	}
	defer c.Close()

	stream := m.eventStreamer.NewStream()
	defer stream.Close()

	go wsHandleControlMessage(c)

	for e := range stream.S {
		err = c.WriteJSON(e)
		if err != nil {
			break
		}
	}
}

func (m *Manager) admAPIStreamDetections(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("StreamLogs, failed to upgrade to websocket: %s", err)
		return
	}
	defer c.Close()

	stream := m.eventStreamer.NewStream()
	defer stream.Close()

	go wsHandleControlMessage(c)

	for e := range stream.S {
		// check if event is associated to a detection
		if _, err := e.Get(&sigPath); err == nil {
			err = c.WriteJSON(e)
			if err != nil {
				break
			}
		}
	}
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

		rt.HandleFunc(AdmAPIEndpointsPath, m.admAPIEndpoints).Methods("GET", "PUT")
		rt.HandleFunc(AdmAPIEndpointsByIDPath, m.admAPIEndpoint).Methods("GET", "DELETE")
		rt.HandleFunc(AdmAPIEndpointCommandPath, m.admAPIEndpointCommand).Methods("GET", "POST")
		rt.HandleFunc(AdmAPIEndpointCommandFieldPath, m.admAPIEndpointCommandField).Methods("GET")
		rt.HandleFunc(AdmAPIEndpointsReportsPath, m.admAPIEndpointsReports).Methods("GET")
		rt.HandleFunc(AdmAPIEndpointLogsPath, m.admAPIEndpointLogs).Methods("GET")
		rt.HandleFunc(AdmAPIEndpointDetectionsPath, m.admAPIEndpointLogs).Methods("GET")
		rt.HandleFunc(AdmAPIEndpointReportPath, m.admAPIEndpointReport).Methods("GET", "DELETE")
		rt.HandleFunc(AdmAPIEndpointsArtifactsPath, m.admAPIArtifacts).Methods("GET")
		rt.HandleFunc(AdmAPIEndpointArtifacts, m.admAPIEndpointArtifacts).Methods("GET")
		rt.HandleFunc(AdmAPIEndpointArtifact, m.admAPIEndpointArtifact).Methods("GET")
		rt.HandleFunc(AdmAPIStatsPath, m.admAPIStats).Methods("GET")
		rt.HandleFunc(AdmAPIRulesPath, m.admAPIRules).Methods("GET", "POST", "DELETE")
		rt.HandleFunc(AdmAPIRulesReloadPath, m.admAPIRulesReload).Methods("GET")
		rt.HandleFunc(AdmAPIRulesSavePath, m.admAPIRulesSave).Methods("GET")
		// WebSocket handlers
		rt.HandleFunc(AdmAPIStreamEvents, m.admAPIStreamEvents)
		rt.HandleFunc(AdmAPIStreamDetections, m.admAPIStreamDetections)

		uri := format("%s:%d", m.Config.AdminAPI.Host, m.Config.AdminAPI.Port)
		m.adminAPI = &http.Server{
			Handler:      rt,
			Addr:         uri,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		if m.Config.TLS.Empty() {
			// Bind to a port and pass our router in
			log.Infof("Running admin HTTP API server on: %s", uri)
			if err := m.adminAPI.ListenAndServe(); err != http.ErrServerClosed {
				log.Panic(err)
			}
		} else {
			// Bind to a port and pass our router in
			log.Infof("Running admin HTTPS API server on: %s", uri)
			if err := m.adminAPI.ListenAndServeTLS(m.Config.TLS.Cert, m.Config.TLS.Key); err != http.ErrServerClosed {
				log.Panic(err)
			}
		}
	}()
}
