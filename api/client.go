package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
)

// ClientConfig structure definition
type ClientConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Proto             string `json:"proto"`
	UUID              string `json:"endpoint-uuid"`
	Key               string `json:"endpoint-key"`
	ServerKey         string `json:"server-key"`
	ServerFingerprint string `json:"server-fingerprint"`
	Unsafe            bool   `json:"unsafe"`
	MaxUploadSize     int64  `json:"max-upload-size"`
}

// ManagerIP returns the IP address of the manager if any, returns nil otherwise
func (cc *ClientConfig) ManagerIP() net.IP {
	if ip := net.ParseIP(cc.Host); ip != nil {
		return ip
	}

	if ips, err := net.LookupIP(cc.Host); err == nil {
		return ips[0]
	}

	return nil
}

// Transport creates an approriate HTTP transport from a configuration
// Cert pinning inspired by: https://medium.com/@zmanian/server-public-key-pinning-in-go-7a57bbe39438
func (cc *ClientConfig) Transport() http.RoundTripper {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: cc.Unsafe})

			if err != nil {
				return c, err
			}

			if cc.ServerFingerprint == "" {
				return c, err
			}
			connstate := c.ConnectionState()
			for _, peercert := range connstate.PeerCertificates {
				der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
				hash := data.Sha256(der)
				if err != nil {
					return c, err
				}

				if hash == cc.ServerFingerprint {
					return c, err
				}
			}
			return c, fmt.Errorf("Server fingerprint not verified")
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ManagerClient structure definition
type ManagerClient struct {
	httpClient http.Client
	config     ClientConfig
	managerIP  net.IP
}

const (
	// UserAgent used by the client
	UserAgent = "Whids-API-Client/1.0"
	// Mega byte size
	Mega = 1 << 20
	// DefaultMaxUploadSize default maximum upload size
	DefaultMaxUploadSize = 100 * Mega
)

var (
	// Hostname the client is running on (initialized in init() function)
	Hostname string
)

func init() {
	var err error
	Hostname, err = os.Hostname()
	if err != nil {
		id := data.Md5([]byte(fmt.Sprintf("%s", time.Now().Format(time.RFC3339Nano))))
		Hostname = fmt.Sprintf("HOST-%s", id)
	}
}

// Sha256StringArray utility
func Sha256StringArray(array []string) string {
	sha256 := sha256.New()
	for _, e := range array {
		sha256.Write([]byte(e))
	}
	return hex.EncodeToString(sha256.Sum(nil))
}

// NewManagerClient creates a new Client to interface with the manager
func NewManagerClient(c *ClientConfig) (*ManagerClient, error) {

	tpt := c.Transport()

	mc := &ManagerClient{
		httpClient: http.Client{Transport: tpt},
		config:     *c,
		managerIP:  c.ManagerIP(),
	}

	// host
	if mc.config.Host == "" {
		return nil, fmt.Errorf("Field \"host\" is missing from configuration")
	}
	// protocol
	if mc.config.Proto == "" {
		mc.config.Proto = "https"
	}

	switch mc.config.Proto {
	case "http", "https":
	default:
		return nil, fmt.Errorf("Protocol not supported (only http(s))")
	}

	// key
	if mc.config.Key == "" {
		return nil, fmt.Errorf("Field \"key\" is missing from configuration")
	}

	return mc, nil
}

// Prepare prepares a http.Request to be sent to the manager
func (m *ManagerClient) Prepare(method, url string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, m.buildURI(url), body)

	if err == nil {
		r.Header.Add("User-Agent", UserAgent)
		r.Header.Add("Hostname", Hostname)
		r.Header.Add("UUID", m.config.UUID)
		r.Header.Add("Api-Key", m.config.Key)
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
	return m.config.ServerKey != ""
}

// IsServerUp returns true if manager server is up
func (m *ManagerClient) IsServerUp() bool {
	get, err := m.Prepare("GET", GetServerKeyURL, nil)
	if err != nil {
		log.Errorf("IsServerUp cannot create server key request: %s", err)
		return false
	}
	resp, err := m.httpClient.Do(get)
	if err != nil {
		log.Errorf("IsServerUp cannot issue server key request: %s", err)
		return false
	}

	if resp != nil {
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}
	return false
}

// IsServerAuthenticated returns true if the server is authenticated and thus can be trusted
func (m *ManagerClient) IsServerAuthenticated() (auth bool, up bool) {
	if m.IsServerAuthEnforced() {
		get, err := m.Prepare("GET", GetServerKeyURL, nil)
		if err != nil {
			log.Errorf("IsServerAuthenticated cannot create server key request: %s", err)
			return false, false
		}
		resp, err := m.httpClient.Do(get)
		if err != nil {
			log.Errorf("IsServerAuthenticated cannot issue server key request: %s", err)
			return false, false
		}
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				key, _ := ioutil.ReadAll(resp.Body)
				if m.config.ServerKey == string(key) {
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
	return fmt.Sprintf("%s://%s:%d/%s", m.config.Proto, m.config.Host, m.config.Port, url)
}

// GetRulesSha256 returns the sha256 string of the latest batch of rules available on the server
func (m *ManagerClient) GetRulesSha256() (string, error) {
	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", GetRulesSha256URL, nil)
		if err != nil {
			return "", fmt.Errorf("GetRulesSha256 failed to prepare request: %s", err)
		}

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("GetRulesSha256 failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("Failed to retrieve rules sha256, unexpected HTTP status code %d", resp.StatusCode)
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

// GetContainer retrieves a given container from the manager
func (m *ManagerClient) GetContainer(name string) ([]string, error) {
	ctn := make([]string, 0)

	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", strings.Replace(GetContainerURL, "{name}", name, 1), nil)
		if err != nil {
			return ctn, fmt.Errorf("GetContainer failed to prepare request: %s", err)
		}

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return ctn, fmt.Errorf("GetContainer failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return ctn, fmt.Errorf("Failed to retrieve container, unexpected HTTP status code %d", resp.StatusCode)
			}
			dec := json.NewDecoder(resp.Body)
			if err = dec.Decode(&ctn); err != nil {
				return ctn, fmt.Errorf("GetContainer failed to decode container")
			}
		}
	}
	return ctn, nil
}

// GetContainersList retrieves the names of the containers available in the manager
func (m *ManagerClient) GetContainersList() ([]string, error) {
	ctn := make([]string, 0)

	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", GetContainerListURL, nil)
		if err != nil {
			return ctn, fmt.Errorf("GetContainersList failed to prepare request: %s", err)
		}

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return ctn, fmt.Errorf("GetContainersList failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return ctn, fmt.Errorf("Failed to retrieve containers list, unexpected HTTP status code %d", resp.StatusCode)
			}
			dec := json.NewDecoder(resp.Body)
			if err = dec.Decode(&ctn); err != nil {
				return ctn, fmt.Errorf("GetContainersList failed to decode container list")
			}
		}
	}
	return ctn, nil
}

// GetContainerSha256 retrieves a given container from the manager
func (m *ManagerClient) GetContainerSha256(name string) (string, error) {

	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", strings.Replace(GetContainerSha256URL, "{name}", name, 1), nil)
		if err != nil {
			return "", fmt.Errorf("GetContainerSha256 failed to prepare request: %s", err)
		}

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("GetContainerSha256 failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("Failed to retrieve container sha256, unexpected HTTP status code %d", resp.StatusCode)
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
		req, err := m.Prepare("GET", GetRulesURL, nil)
		if err != nil {
			return "", fmt.Errorf("GetRules failed to prepare request: %s", err)
		}

		resp, err := m.httpClient.Do(req)
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

// PrepareFileUpload prepares a FileUpload from several parameters
func (m *ManagerClient) PrepareFileUpload(path, guid, evthash, filename string) (*FileUpload, error) {
	fu := FileUpload{Name: filename, GUID: guid, EventHash: evthash}
	if fsutil.IsFile(path) {
		if !m.isFileAboveUploadLimit(path) {
			fd, err := os.Open(path)
			if err != nil {
				return &fu, err
			}
			defer fd.Close()
			if fu.Content, err = ioutil.ReadAll(fd); err != nil {
				return &fu, err
			}
			return &fu, nil
		}
		return &fu, fmt.Errorf("Dump size above limit")
	}
	return &fu, os.ErrNotExist
}

func (m *ManagerClient) isFileAboveUploadLimit(path string) bool {
	if fsutil.IsFile(path) {
		stats, err := os.Stat(path)
		if err == nil {
			return stats.Size() > m.config.MaxUploadSize
		}
	}
	return true
}

// PostDump client helper to upload a file to the Manager
func (m *ManagerClient) PostDump(f *FileUpload) error {
	if auth, up := m.IsServerAuthenticated(); auth {
		if up {
			body, err := json.Marshal(f)
			if err != nil {
				return fmt.Errorf("PostDump failed to JSON encode")
			}

			req, err := m.Prepare("POST", PostDumpURL, bytes.NewBuffer(body))

			if err != nil {
				return fmt.Errorf("PostDump failed to prepare request: %s", err)
			}

			resp, err := m.httpClient.Do(req)
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
			req, err := m.PrepareGzip("POST", PostLogsURL, r)

			if err != nil {
				return fmt.Errorf("PostLogs failed to prepare request: %s", err)
			}

			resp, err := m.httpClient.Do(req)
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

// ExecuteCommand executes a Command on the endpoint and return the result
// to the manager. NB: this method is blocking due to Command.Run function call
func (m *ManagerClient) ExecuteCommand() error {
	if auth, _ := m.IsServerAuthenticated(); auth {
		env := AliasEnv{m.managerIP}
		command := NewCommandWithEnv(&env)

		// getting command to be executed
		req, err := m.Prepare("GET", CommandURL, nil)
		if err != nil {
			return fmt.Errorf("ExecuteCommand failed to prepare request: %s", err)
		}

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("ExecuteCommand failed to issue HTTP request: %s", err)
		}

		// if there is no command to execute, the server replies with this status code
		if resp.StatusCode == http.StatusNoContent {
			// nothing else to do
			return nil
		}

		jsonCommand, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("ExecuteCommand failed to read HTTP response body: %s", err)
		}

		// unmarshal command to be executed
		if err := json.Unmarshal(jsonCommand, &command); err != nil {
			return fmt.Errorf("ExecuteCommand failed to unmarshal command: %s", err)
		}

		// running the command, this is a blocking function, it waits the command to finish
		if err := command.Run(); err != nil {
			log.Errorf("ExecuteCommand failed to run command \"%s\": %s", command, err)
		}

		// stripping unecessary content to send back the command
		command.Strip()
		for fn, ff := range command.Fetch {
			log.Infof("file: %s len: %d error: %s", fn, len(ff.Data), ff.Error)
		}
		// command should now contain stdout and stderr
		jsonCommand, err = json.Marshal(command)
		if err != nil {
			return fmt.Errorf("ExecuteCommand failed to marshal command")
		}

		// send back the response
		req, err = m.PrepareGzip("POST", CommandURL, bytes.NewBuffer(jsonCommand))
		if err != nil {
			return fmt.Errorf("ExecuteCommand failed to prepare POST request")
		}

		resp, err = m.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("ExecuteCommand failed to issue HTTP request: %s", err)
		}

		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("ExecuteCommand failed to send command results, unexpected HTTP status code %d", resp.StatusCode)
			}
		}
		return nil
	}
	return fmt.Errorf("ExecuteCommand failed, server cannot be authenticated")
}

// Close closes idle connections from underlying transport
func (m *ManagerClient) Close() {
	m.httpClient.CloseIdleConnections()
}
