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
	aconfig "github.com/0xrawsec/whids/agent/config"
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

	ErrNothingToDo              = errors.New("nothing to do")
	ErrServerUnauthenticated    = errors.New("server authentication failed")
	ErrUnexpectedNilResponse    = errors.New("unexpected nil response")
	ErrUnexpectedResponseStatus = errors.New("unexpected response status code")
	ErrNoSysmonConfig           = errors.New("no sysmon config available in manager")
	ErrNoAgentConfig            = errors.New("no sysmon config available in manager")
)

func init() {
	var err error
	Hostname, err = os.Hostname()
	if err != nil {
		id := data.Md5([]byte(time.Now().Format(time.RFC3339Nano)))
		Hostname = fmt.Sprintf("HOST-%s", id)
	}
}

func ValidateResponse(resp *http.Response, status ...int) error {
	if resp == nil {
		return ErrUnexpectedNilResponse
	}

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
func (m *ManagerClient) Prepare(method, url string, body io.Reader) (r *http.Request, err error) {
	if r, err = http.NewRequest(method, m.buildURI(url), body); err != nil {
		return
	}

	r.Header.Add("User-Agent", UserAgent)
	r.Header.Add(api.EndpointHostnameHeader, Hostname)
	// the address used by the client to connect to the manager
	r.Header.Add(api.EndpointIPHeader, m.Config.LocalAddr())
	r.Header.Add(api.EndpointUUIDHeader, m.Config.UUID)
	r.Header.Add(api.AuthKeyHeader, m.Config.Key)

	return
}

func (m *ManagerClient) PrepareAndDo(method, url string, body io.Reader) (resp *http.Response, err error) {
	var req *http.Request

	if req, err = m.Prepare(method, url, body); err != nil {
		return
	}

	return m.HTTPClient.Do(req)
}

func (m *ManagerClient) PrepareAndDoGzip(method, url string, body io.Reader) (resp *http.Response, err error) {
	var req *http.Request

	if req, err = m.PrepareGzip(method, url, body); err != nil {
		return
	}

	return m.HTTPClient.Do(req)
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
func (m *ManagerClient) IsServerUp() (up bool) {
	var err error
	var resp *http.Response

	if resp, err = m.PrepareAndDo("GET", api.EptAPIServerKeyPath, nil); err != nil {
		return
	}

	defer resp.Body.Close()
	return ValidateResponse(resp, http.StatusOK) == nil
}

// AuthenticateServer returns nil if server is authenticated (or if server authentication is not enforced)
// otherwise it returns ErrServerUnauthenticated
func (m *ManagerClient) AuthenticateServer() (err error) {
	var resp *http.Response

	if !m.IsServerAuthEnforced() {
		return
	}

	if resp, err = m.PrepareAndDo("GET", api.EptAPIServerKeyPath, nil); err != nil {
		return fmt.Errorf("%w, %s", ErrServerUnauthenticated, err)
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return fmt.Errorf("%w, %s", ErrServerUnauthenticated, err)
	}

	if resp == nil {
		return fmt.Errorf("%w, received empty response from server", ErrServerUnauthenticated)
	}

	key := respBodyToString(resp)
	if key != m.Config.ServerKey {
		return fmt.Errorf("%w, keys are not matching", ErrServerUnauthenticated)
	}

	return
}

func (m *ManagerClient) buildURI(url string) string {
	url = strings.Trim(url, "/")
	return fmt.Sprintf("%s://%s:%d/%s", m.Config.Proto, m.Config.Host, m.Config.Port, url)
}

// GetRulesSha256 returns the sha256 string of the latest batch of rules available on the server
func (m *ManagerClient) GetRulesSha256() (string, error) {

	if err := m.AuthenticateServer(); err != nil {
		return "", err
	}

	resp, err := m.PrepareAndDo("GET", api.EptAPIRulesSha256Path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to issue HTTP request: %s", err)
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return "", err
	}

	return respBodyAsString(resp)
}

// GetIoCs get IoCs from manager
func (m *ManagerClient) GetIoCs() (iocs []string, err error) {
	var resp *http.Response

	iocs = make([]string, 0)

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if resp, err = m.PrepareAndDo("GET", api.EptAPIIoCsPath, nil); err != nil {
		return
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(&iocs); err != nil {
		return
	}

	return
}

// GetIoCsSha256 retrieves a sha256 from the IoCs available in the manager
func (m *ManagerClient) GetIoCsSha256() (sha string, err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if resp, err = m.PrepareAndDo("GET", api.EptAPIIoCsSha256Path, nil); err != nil {
		return
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return respBodyAsString(resp)
}

// GetRules retrieve the latest batch of Gene rules available on the server
func (m *ManagerClient) GetRules() (rules string, err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if resp, err = m.PrepareAndDo("GET", api.EptAPIRulesPath, nil); err != nil {
		return
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return respBodyAsString(resp)
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
func (m *ManagerClient) PostDump(f *FileUpload) (err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)

	if err = enc.Encode(f); err != nil {
		return err
	}

	if resp, err = m.PrepareAndDo("POST", api.EptAPIPostDumpPath, buf); err != nil {
		return
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return
}

// PostLogs posts logs to be collected
func (m *ManagerClient) PostLogs(r io.Reader) (err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if resp, err = m.PrepareAndDoGzip("POST", api.EptAPIPostLogsPath, r); err != nil {
		return
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return
}

var ()

func (m *ManagerClient) PostCommand(command *api.EndpointCommand) (err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	// stripping unecessary content to send back the command
	command.Strip()

	// command should now contain stdout and stderr
	jsonCommand, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("PostCommand failed to marshal command")
	}

	// send back the response
	if resp, err = m.PrepareAndDoGzip("POST", api.EptAPICommandPath, bytes.NewBuffer(jsonCommand)); err != nil {
		return
	}

	defer resp.Body.Close()
	if ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return nil

}

func (m *ManagerClient) FetchCommand() (command *api.EndpointCommand, err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	// getting command to be executed
	if resp, err = m.PrepareAndDo("GET", api.EptAPICommandPath, nil); err != nil {
		return
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusNoContent, http.StatusOK); err != nil {
		return
	}

	// if there is no command to execute, the server replies with this status code
	if resp.StatusCode == http.StatusNoContent {
		err = ErrNothingToDo
		return
	}

	dec := json.NewDecoder(resp.Body)
	// unmarshal command to be executed
	if err = dec.Decode(&command); err != nil {
		return
	}

	if command != nil {
		command.Runnable()
	}

	return
}

func (m *ManagerClient) PostSystemInfo(info *sysinfo.SystemInfo) (err error) {
	var resp *http.Response
	var data []byte

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if data, err = json.Marshal(info); err != nil {
		return
	}

	if resp, err = m.PrepareAndDoGzip("POST", api.EptAPIPostSystemInfo, bytes.NewBuffer(data)); err != nil {
		return err
	}

	defer resp.Body.Close()
	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return
}

func (m *ManagerClient) GetSysmonConfigSha256(schemaVersion string) (sha256 string, err error) {
	var req *http.Request
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
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

	if err = ValidateResponse(resp, http.StatusOK, http.StatusNoContent); err == nil {
		if resp.StatusCode == http.StatusNoContent {
			err = ErrNoSysmonConfig
			return
		}
		sha256, err = respBodyAsString(resp)
	}

	return
}

func (m *ManagerClient) GetSysmonConfig(schemaVersion string) (c *sysmon.Config, err error) {
	var req *http.Request
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
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

	if err = ValidateResponse(resp, http.StatusOK, http.StatusNoContent); err == nil {
		if resp.StatusCode == http.StatusNoContent {
			err = ErrNoSysmonConfig
			return
		}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&c)
	}

	return
}

func (m *ManagerClient) GetAgentConfigSha256() (sha256 string, err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if resp, err = m.PrepareAndDo("GET", api.EptAPIConfigSha256Path, nil); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateResponse(resp, http.StatusOK, http.StatusNoContent); err == nil {
		if resp.StatusCode == http.StatusNoContent {
			err = ErrNoAgentConfig
			return
		}
		sha256 = respBodyToString(resp)
	}

	return
}

func (m *ManagerClient) GetAgentConfig() (config *aconfig.Agent, err error) {
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if resp, err = m.PrepareAndDo("GET", api.EptAPIConfigPath, nil); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateResponse(resp, http.StatusOK, http.StatusNoContent); err == nil {
		if resp.StatusCode == http.StatusNoContent {
			err = ErrNoAgentConfig
			return
		}
		// decoding configuration
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&config)
	}

	return
}

func (m *ManagerClient) PostAgentConfig(c *aconfig.Agent) (err error) {
	var b []byte
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if b, err = utils.Json(c); err != nil {
		return
	}

	if resp, err = m.PrepareAndDoGzip("POST", api.EptAPIConfigPath, bytes.NewBuffer(b)); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateResponse(resp, http.StatusOK); err != nil {
		return
	}

	return
}

func (m *ManagerClient) ListTools() (t map[string]*tools.Tool, err error) {
	var req *http.Request
	var resp *http.Response

	if err = m.AuthenticateServer(); err != nil {
		return
	}

	if req, err = m.Prepare("GET", api.EptAPITools, nil); err != nil {
		return
	}

	requestAddURLParam(req, api.QpOS, los.OS)

	if resp, err = m.HTTPClient.Do(req); err != nil {
		return
	}

	defer resp.Body.Close()

	if err = ValidateResponse(resp, http.StatusOK); err == nil {
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&t)
	}

	return
}

func (m *ManagerClient) GetTool(hash string) (t *tools.Tool, err error) {
	var req *http.Request
	var resp *http.Response
	var tools map[string]*tools.Tool

	if err = m.AuthenticateServer(); err != nil {
		return
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

	if err = ValidateResponse(resp, http.StatusOK); err == nil {
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
