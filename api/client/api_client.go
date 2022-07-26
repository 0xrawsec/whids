package client

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/agent/sysinfo"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/api/client/config"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/sysmon"
	"github.com/0xrawsec/whids/tools"
	"github.com/0xrawsec/whids/utils"
)

const (
	// UserAgent used by the client
	UserAgent = "Whids-API-Client/1.0"
	// Mega byte size
	Mega = 1 << 20
)

var (
	// Hostname the client is running on (initialized in init() function)
	Hostname string

	ErrServerUnauthenticated    = errors.New("server authentication failed")
	ErrUnexpectedResponseStatus = errors.New("unexpected response status code")
	ErrNoSysmonConfig           = errors.New("no sysmon config available in manager")
)

func init() {
	var err error
	Hostname, err = os.Hostname()
	if err != nil {
		id := data.Md5([]byte(time.Now().Format(time.RFC3339Nano)))
		Hostname = fmt.Sprintf("HOST-%s", id)
	}
}

func ValidateRespStatus(resp *http.Response, status ...int) error {
	for _, s := range status {
		if resp.StatusCode == s {
			return nil
		}
	}
	return fmt.Errorf("%w %d: %s", ErrUnexpectedResponseStatus, resp.StatusCode, respBodyToString(resp))
}

// ManagerClient structure definition
type ManagerClient struct {
	Config *config.Client

	ManagerIP  net.IP
	HTTPClient http.Client
}

// NewManagerClient creates a new Client to interface with the manager
func NewManagerClient(c *config.Client) (*ManagerClient, error) {

	tpt := c.Transport()

	mc := &ManagerClient{
		Config:     c,
		ManagerIP:  c.ManagerIP(),
		HTTPClient: http.Client{Transport: tpt},
	}

	// host
	if mc.Config.Host == "" {
		return nil, fmt.Errorf("field \"host\" is missing from configuration")
	}
	// protocol
	if mc.Config.Proto == "" {
		mc.Config.Proto = "https"
	}

	switch mc.Config.Proto {
	case "http", "https":
	default:
		return nil, fmt.Errorf("protocol not supported (only http(s))")
	}

	// key
	if mc.Config.Key == "" {
		return nil, fmt.Errorf("field \"key\" is missing from configuration")
	}

	return mc, nil
}

// Prepare prepares a http.Request to be sent to the manager
func (m *ManagerClient) Prepare(method, url string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, m.buildURI(url), body)

	if err == nil {
		r.Header.Add("User-Agent", UserAgent)
		r.Header.Add(api.EndpointHostnameHeader, Hostname)
		// the address used by the client to connect to the manager
		r.Header.Add(api.EndpointIPHeader, m.Config.LocalAddr())
		r.Header.Add(api.EndpointUUIDHeader, m.Config.UUID)
		r.Header.Add(api.AuthKeyHeader, m.Config.Key)
	}
	return r, err
}

// PrepareGzip prepares a http.Request gzip encoded to be sent to the manager
func (m *ManagerClient) PrepareGzip(method, url string, body io.Reader) (*http.Request, error) {
	// Prepare gzip content
	compBody := new(bytes.Buffer)
	w := gzip.NewWriter(compBody)
	b, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("PostLogs failed to prepare body")
	}
	w.Write(b)
	w.Close()

	r, err := m.Prepare(method, url, bytes.NewBuffer(compBody.Bytes()))

	// setting header
	r.Header.Add("Content-Encoding", "gzip")

	return r, err
}

// IsServerAuthEnforced returns true if server authentication is requested by the client
func (m *ManagerClient) IsServerAuthEnforced() bool {
	return m.Config.ServerKey != ""
}

// IsServerUp returns true if manager server is up
func (m *ManagerClient) IsServerUp() bool {
	get, err := m.Prepare("GET", api.EptAPIServerKeyPath, nil)
	if err != nil {
		log.Errorf("IsServerUp cannot create server key request: %s", err)
		return false
	}
	resp, err := m.HTTPClient.Do(get)
	if err != nil {
		return false
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	return resp.StatusCode == 200
}

// IsServerAuthenticated returns true if the server is authenticated and thus can be trusted
func (m *ManagerClient) IsServerAuthenticated() (auth bool, up bool) {
	if m.IsServerAuthEnforced() {
		get, err := m.Prepare("GET", api.EptAPIServerKeyPath, nil)
		if err != nil {
			log.Errorf("IsServerAuthenticated cannot create server key request: %s", err)
			return false, false
		}
		resp, err := m.HTTPClient.Do(get)
		if err != nil {
			log.Errorf("IsServerAuthenticated cannot issue server key request: %s", err)
			return false, false
		}
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				key, _ := ioutil.ReadAll(resp.Body)
				if m.Config.ServerKey == string(key) {
					// if the server can be authenticated
					return true, true
				}
				log.Warn("Failed to authenticate remote server")
				// if the server is not authenticated
				return false, true
			}
			return false, false
		}
		return false, false
	}
	return true, m.IsServerUp()
}

func (m *ManagerClient) buildURI(url string) string {
	url = strings.Trim(url, "/")
	return fmt.Sprintf("%s://%s:%d/%s", m.Config.Proto, m.Config.Host, m.Config.Port, url)
}

// GetRulesSha256 returns the sha256 string of the latest batch of rules available on the server
func (m *ManagerClient) GetRulesSha256() (string, error) {
	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", api.EptAPIRulesSha256Path, nil)
		if err != nil {
			return "", fmt.Errorf("GetRulesSha256 failed to prepare request: %s", err)
		}

		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("SetRulesSha256 failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("failed to retrieve rules sha256, unexpected HTTP status code %d", resp.StatusCode)
			}
			sha256, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return "", fmt.Errorf("GetRulesSha256 failed to read HTTP response body: %s", err)
			}
			return string(sha256), nil
		}
	}
	return "", nil
}

// GetIoCs get IoCs from manager
func (m *ManagerClient) GetIoCs() ([]string, error) {
	ctn := make([]string, 0)

	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", api.EptAPIIoCsPath, nil)
		if err != nil {
			return ctn, fmt.Errorf("GetContainer failed to prepare request: %s", err)
		}

		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			return ctn, fmt.Errorf("GetContainer failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return ctn, fmt.Errorf("failed to retrieve container, unexpected HTTP status code %d", resp.StatusCode)
			}
			dec := json.NewDecoder(resp.Body)
			if err = dec.Decode(&ctn); err != nil {
				return ctn, fmt.Errorf("GetContainer failed to decode container")
			}
		}
	}
	return ctn, nil
}

// GetIoCsSha256 retrieves a sha256 from the IoCs available in the manager
func (m *ManagerClient) GetIoCsSha256() (string, error) {

	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", api.EptAPIIoCsSha256Path, nil)
		if err != nil {
			return "", fmt.Errorf("GetContainerSha256 failed to prepare request: %s", err)
		}

		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("GetContainerSha256 failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("failed to retrieve container sha256, unexpected HTTP status code %d", resp.StatusCode)
			}
			sha256, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return "", fmt.Errorf("GetContainerSha256 failed to read HTTP response body: %s", err)
			}
			return string(sha256), nil
		}
	}
	return "", nil
}

// GetRules retrieve the latest batch of Gene rules available on the server
func (m *ManagerClient) GetRules() (string, error) {
	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", api.EptAPIRulesPath, nil)
		if err != nil {
			return "", fmt.Errorf("GetRules failed to prepare request: %s", err)
		}

		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("GetRules failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("GetRules failed to retrieve rules, unexpected HTTP status code %d", resp.StatusCode)
			}
			rules, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return "", fmt.Errorf("GetRules failed to read HTTP response body: %s", err)
			}
			return string(rules), nil
		}
	}
	return "", nil
}

func (m *ManagerClient) IsFileAboveUploadLimit(path string) bool {
	if fsutil.IsFile(path) {
		stats, err := os.Stat(path)
		if err == nil {
			return stats.Size() > m.Config.MaxUploadSize
		}
	}
	return true
}

// PostDump client helper to upload a file to the Manager
func (m *ManagerClient) PostDump(f *FileUpload) error {
	if auth, up := m.IsServerAuthenticated(); auth {
		if up {
			buf := new(bytes.Buffer)
			enc := json.NewEncoder(buf)

			if err := enc.Encode(f); err != nil {
				return fmt.Errorf("PostDump failed to encode to JSON")
			}

			req, err := m.Prepare("POST", api.EptAPIPostDumpPath, buf)

			if err != nil {
				return fmt.Errorf("PostDump failed to prepare request: %s", err)
			}

			resp, err := m.HTTPClient.Do(req)
			if err != nil {
				return fmt.Errorf("PostDump failed to issue HTTP request: %s", err)
			}

			if resp != nil {
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					return fmt.Errorf("PostDump failed to send dump, unexpected HTTP status code %d", resp.StatusCode)
				}
				return nil
			}
			return fmt.Errorf("PostDump failed to send dump, nil HTTP response")
		}
		return fmt.Errorf("PostDump failed because manager is down")
	}
	return fmt.Errorf("PostDump failed, server cannot be authenticated")
}

// PostLogs posts logs to be collected
func (m *ManagerClient) PostLogs(r io.Reader) error {
	if auth, up := m.IsServerAuthenticated(); auth {
		if up {
			req, err := m.PrepareGzip("POST", api.EptAPIPostLogsPath, r)

			if err != nil {
				return fmt.Errorf("PostLogs failed to prepare request: %s", err)
			}

			resp, err := m.HTTPClient.Do(req)
			if err != nil {
				return fmt.Errorf("PostLogs failed to issue HTTP request: %s", err)
			}

			if resp != nil {
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					return fmt.Errorf("PostLogs failed to send logs, unexpected HTTP status code %d", resp.StatusCode)
				}
				return nil
			}
			return fmt.Errorf("PostLogs failed to send logs, nil HTTP response")
		}
		return fmt.Errorf("PostLogs failed because manager is down, logs not sent")
	}
	return fmt.Errorf("PostLogs failed, server cannot be authenticated")
}

var (
	ErrNothingToDo = fmt.Errorf("nothing to do")
)

func (m *ManagerClient) PostCommand(command *api.EndpointCommand) error {
	if auth, _ := m.IsServerAuthenticated(); auth {
		// stripping unecessary content to send back the command
		command.Strip()

		// command should now contain stdout and stderr
		jsonCommand, err := json.Marshal(command)
		if err != nil {
			return fmt.Errorf("PostCommand failed to marshal command")
		}

		// send back the response
		req, err := m.PrepareGzip("POST", api.EptAPICommandPath, bytes.NewBuffer(jsonCommand))
		if err != nil {
			return fmt.Errorf("PostCommand failed to prepare POST request")
		}

		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("PostCommand failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("PostCommand failed to send command results, unexpected HTTP status code %d", resp.StatusCode)
			}
		}
		return nil
	}
	return fmt.Errorf("PostCommand failed, server cannot be authenticated")

}

func (m *ManagerClient) FetchCommand() (*api.EndpointCommand, error) {
	command := api.NewEndpointCommand()
	if auth, _ := m.IsServerAuthenticated(); auth {
		// getting command to be executed
		req, err := m.Prepare("GET", api.EptAPICommandPath, nil)
		if err != nil {
			return command, fmt.Errorf("FetchCommand failed to prepare request: %s", err)
		}

		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			return command, fmt.Errorf("FetchCommand failed to issue HTTP request: %s", err)
		}

		// if there is no command to execute, the server replies with this status code
		if resp.StatusCode == http.StatusNoContent {
			// nothing else to do
			return command, ErrNothingToDo
		}

		if resp.StatusCode == http.StatusOK {
			jsonCommand, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return command, fmt.Errorf("FetchCommand failed to read HTTP response body: %s", err)
			}

			// unmarshal command to be executed
			if err := json.Unmarshal(jsonCommand, &command); err != nil {
				return command, fmt.Errorf("FetchCommand failed to unmarshal command: %s", err)
			}

			return command, nil
		}
		return command, fmt.Errorf("FetchCommand unexpected HTTP status %d", resp.StatusCode)

	}
	return command, fmt.Errorf("FetchCommand failed, server cannot be authenticated")
}

func (m *ManagerClient) PostSystemInfo(info *sysinfo.SystemInfo) error {
	funcName := utils.GetCurFuncName()
	if auth, _ := m.IsServerAuthenticated(); auth {
		if b, err := json.Marshal(info); err != nil {
			return fmt.Errorf("%s failed to marshal data: %s", funcName, err)
		} else {
			if req, err := m.PrepareGzip("POST", api.EptAPIPostSystemInfo, bytes.NewBuffer(b)); err != nil {
				return err
			} else {
				if resp, err := m.HTTPClient.Do(req); err != nil {
					return fmt.Errorf("%s failed to issue HTTP request: %s", funcName, err)
				} else {
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("%s received bad status code %d: %s", funcName, resp.StatusCode, respBodyToString(resp))
					} else {
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("%s %w", funcName, ErrServerUnauthenticated)
}

func (m *ManagerClient) GetSysmonConfigSha256(schemaVersion string) (sha256 string, err error) {
	var req *http.Request
	var resp *http.Response

	if auth, _ := m.IsServerAuthenticated(); !auth {
		return "", ErrServerUnauthenticated
	}

	if req, err = m.Prepare("GET", api.EptAPISysmonConfigSha256Path, nil); err != nil {
		return
	}

	requestAddURLParam(req, api.QpOS, los.OS)
	requestAddURLParam(req, api.QpVersion, schemaVersion)

	if resp, err = m.HTTPClient.Do(req); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateRespStatus(resp, http.StatusOK, http.StatusNoContent); err == nil {
		if resp.StatusCode == http.StatusNoContent {
			err = ErrNoSysmonConfig
			return
		}
		sha256 = respBodyToString(resp)
	}

	return
}

func (m *ManagerClient) GetSysmonConfig(schemaVersion string) (c *sysmon.Config, err error) {
	var req *http.Request
	var resp *http.Response

	if auth, _ := m.IsServerAuthenticated(); !auth {
		return nil, ErrServerUnauthenticated
	}

	if req, err = m.Prepare("GET", api.EptAPISysmonConfigPath, nil); err != nil {
		return
	}

	requestAddURLParam(req, api.QpOS, los.OS)
	requestAddURLParam(req, api.QpVersion, schemaVersion)

	if resp, err = m.HTTPClient.Do(req); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateRespStatus(resp, http.StatusOK, http.StatusNoContent); err == nil {
		if resp.StatusCode == http.StatusNoContent {
			err = ErrNoSysmonConfig
			return
		}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&c)
	}

	return
}

func (m *ManagerClient) ListTools() (t map[string]*tools.Tool, err error) {
	var req *http.Request
	var resp *http.Response

	if auth, _ := m.IsServerAuthenticated(); !auth {
		return nil, ErrServerUnauthenticated
	}

	if req, err = m.Prepare("GET", api.EptAPITools, nil); err != nil {
		return
	}

	requestAddURLParam(req, api.QpOS, los.OS)

	if resp, err = m.HTTPClient.Do(req); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateRespStatus(resp, http.StatusOK); err == nil {
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&t)
	}

	return
}

func (m *ManagerClient) GetTool(hash string) (t *tools.Tool, err error) {
	var req *http.Request
	var resp *http.Response
	var tools map[string]*tools.Tool

	if auth, _ := m.IsServerAuthenticated(); !auth {
		return nil, ErrServerUnauthenticated
	}

	if req, err = m.Prepare("GET", api.EptAPITools, nil); err != nil {
		return
	}

	requestAddURLParam(req, api.QpOS, los.OS)
	requestAddURLParam(req, api.QpHash, hash)
	requestAddURLParam(req, api.QpBinary, "true")

	if resp, err = m.HTTPClient.Do(req); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateRespStatus(resp, http.StatusOK); err == nil {
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&tools)
		if len(tools) > 0 {
			for _, tool := range tools {
				t = tool
				break
			}

		}
	}

	return
}

// Close closes idle connections from underlying transport
func (m *ManagerClient) Close() {
	m.HTTPClient.CloseIdleConnections()
}
