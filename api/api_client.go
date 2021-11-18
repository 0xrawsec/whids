package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	Proto             string `toml:"proto" comment:"Protocol to use to connect to manager (http or https)"`
	Host              string `toml:"host" comment:"Hostname or IP of the manager"`
	Port              int    `toml:"port" comment:"Port at which endpoint API is running on manager server"`
	UUID              string `toml:"endpoint-uuid" comment:"Endpoint UUID configured on manager used to authenticate this endpoint"`
	Key               string `toml:"endpoint-key" comment:"Endpoint key configured on manager used to authenticate this endpoint"`
	ServerKey         string `toml:"server-key" comment:"Key configured on manager, used to authenticate server on this endpoint\n This settings does not protect from MITM, so configuring server\n certificate pinning is recommended."`
	ServerFingerprint string `toml:"server-fingerprint" comment:"Configure manager certificate pinning\n Put here the manager's certificate fingerprint"`
	Unsafe            bool   `toml:"unsafe" comment:"Allow unsafe HTTPS connection"`
	MaxUploadSize     int64  `toml:"max-upload-size" comment:"Maximum allowed upload size"`

	localAddr string
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

func (cc *ClientConfig) DialContext(ctx context.Context, network, addr string) (con net.Conn, err error) {
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	con, err = dialer.DialContext(ctx, network, addr)

	if err == nil && con != nil {
		if addr, ok := con.LocalAddr().(*net.TCPAddr); ok {
			cc.localAddr = addr.IP.String()
		}
	}

	return
}

func (cc *ClientConfig) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: cc.Unsafe})

	if err != nil {
		return c, err
	}

	if c != nil {
		if addr, ok := c.LocalAddr().(*net.TCPAddr); ok {
			cc.localAddr = addr.IP.String()
		}
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
	return c, fmt.Errorf("server fingerprint not verified")
}

// Transport creates an approriate HTTP transport from a configuration
// Cert pinning inspired by: https://medium.com/@zmanian/server-public-key-pinning-in-go-7a57bbe39438
func (cc *ClientConfig) Transport() http.RoundTripper {
	return &http.Transport{
		Proxy: nil,
		/*DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,*/
		DialContext:           cc.DialContext,
		DialTLSContext:        cc.DialTLSContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ManagerClient structure definition
type ManagerClient struct {
	config *ClientConfig

	ManagerIP  net.IP
	HTTPClient http.Client
}

const (
	// UserAgent used by the client
	UserAgent = "Whids-API-Client/1.0"
	// Mega byte size
	Mega = 1 << 20
)

var (
	// Hostname the client is running on (initialized in init() function)
	Hostname string
)

func init() {
	var err error
	Hostname, err = os.Hostname()
	if err != nil {
		id := data.Md5([]byte(time.Now().Format(time.RFC3339Nano)))
		Hostname = fmt.Sprintf("HOST-%s", id)
	}
}

// NewManagerClient creates a new Client to interface with the manager
func NewManagerClient(c *ClientConfig) (*ManagerClient, error) {

	tpt := c.Transport()

	mc := &ManagerClient{
		config:     c,
		ManagerIP:  c.ManagerIP(),
		HTTPClient: http.Client{Transport: tpt},
	}

	// host
	if mc.config.Host == "" {
		return nil, fmt.Errorf("field \"host\" is missing from configuration")
	}
	// protocol
	if mc.config.Proto == "" {
		mc.config.Proto = "https"
	}

	switch mc.config.Proto {
	case "http", "https":
	default:
		return nil, fmt.Errorf("protocol not supported (only http(s))")
	}

	// key
	if mc.config.Key == "" {
		return nil, fmt.Errorf("field \"key\" is missing from configuration")
	}

	return mc, nil
}

// Prepare prepares a http.Request to be sent to the manager
func (m *ManagerClient) Prepare(method, url string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, m.buildURI(url), body)

	if err == nil {
		r.Header.Add("User-Agent", UserAgent)
		r.Header.Add(EndpointHostnameHeader, Hostname)
		// the address used by the client to connect to the manager
		r.Header.Add(EndpointIPHeader, m.config.localAddr)
		r.Header.Add(EndpointUUIDHeader, m.config.UUID)
		r.Header.Add(AuthKeyHeader, m.config.Key)
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
	get, err := m.Prepare("GET", EptAPIServerKeyPath, nil)
	if err != nil {
		log.Errorf("IsServerUp cannot create server key request: %s", err)
		return false
	}
	resp, err := m.HTTPClient.Do(get)
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
		get, err := m.Prepare("GET", EptAPIServerKeyPath, nil)
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
		req, err := m.Prepare("GET", EptAPIRulesSha256Path, nil)
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
		req, err := m.Prepare("GET", EptAPIIoCsPath, nil)
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

// GetIoCsSha256 retrieves a sha256 from the IoCs available in the manager
func (m *ManagerClient) GetIoCsSha256() (string, error) {

	if auth, _ := m.IsServerAuthenticated(); auth {
		req, err := m.Prepare("GET", EptAPIIoCsSha256Path, nil)
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
		req, err := m.Prepare("GET", EptAPIRulesPath, nil)
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
			return stats.Size() > m.config.MaxUploadSize
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

			req, err := m.Prepare("POST", EptAPIPostDumpPath, buf)

			if err != nil {
				return fmt.Errorf("PostDump failed to prepare request: %s", err)
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
			req, err := m.PrepareGzip("POST", EptAPIPostLogsPath, r)

			if err != nil {
				return fmt.Errorf("PostLogs failed to prepare request: %s", err)
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

func (m *ManagerClient) PostCommand(command *Command) error {
	if auth, _ := m.IsServerAuthenticated(); auth {
		// stripping unecessary content to send back the command
		command.Strip()

		// command should now contain stdout and stderr
		jsonCommand, err := json.Marshal(command)
		if err != nil {
			return fmt.Errorf("PostCommand failed to marshal command")
		}

		// send back the response
		req, err := m.PrepareGzip("POST", EptAPICommandPath, bytes.NewBuffer(jsonCommand))
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

func (m *ManagerClient) FetchCommand() (*Command, error) {
	command := NewCommand()
	if auth, _ := m.IsServerAuthenticated(); auth {
		// getting command to be executed
		req, err := m.Prepare("GET", EptAPICommandPath, nil)
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
	return command, fmt.Errorf("FetchCommand failed, server cannot be authenticated")
}

// Close closes idle connections from underlying transport
func (m *ManagerClient) Close() {
	m.HTTPClient.CloseIdleConnections()
}
