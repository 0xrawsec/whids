package collector

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
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

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
)

// ClientConfig structure definition
type ClientConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port`
	Proto         string `json:"proto"`
	Key           string `json:"key"`
	ServerKey     string `json:"server-key"`
	Unsafe        bool   `json:"unsafe"`
	MaxUploadSize int64  `json:"max-upload-size"`
}

// ManagerClient structure definition
type ManagerClient struct {
	httpClient    http.Client
	proto         string
	host          string
	port          string
	key           string
	serverKey     string
	maxUploadSize int64
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
	// NoProxyTransport http transport bypassing proxy
	NoProxyTransport http.RoundTripper = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// NoProxyUnsafeTransport http transport bypassing proxy and SSL verification
	NoProxyUnsafeTransport http.RoundTripper = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
)

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
	// Type of HTTP transport to use
	tpt := NoProxyTransport
	if c.Unsafe {
		tpt = NoProxyUnsafeTransport
	}

	mc := &ManagerClient{
		httpClient:    http.Client{Transport: tpt},
		host:          c.Host,
		proto:         c.Proto,
		port:          DefaultPort,
		key:           c.Key,
		serverKey:     c.ServerKey,
		maxUploadSize: DefaultMaxUploadSize,
	}

	// host
	if mc.host == "" {
		return nil, fmt.Errorf("Field \"host\" is missing from configuration")
	}
	// protocol
	if mc.proto == "" {
		mc.proto = "https"
	}
	switch mc.proto {
	case "http", "https":
	default:
		return nil, fmt.Errorf("Protocol not supported (only http(s))")
	}

	// port
	if c.Port > 0 {
		mc.port = fmt.Sprintf("%d", c.Port)
	}

	// key
	if mc.key == "" {
		return nil, fmt.Errorf("Field \"key\" is missing from configuration")
	}

	// server-key
	mc.serverKey = c.ServerKey

	// max-upload-size
	if c.MaxUploadSize > 0 {
		mc.maxUploadSize = c.MaxUploadSize
	}

	return mc, nil
}

// Prepare prepares a http.Request to be sent to the manager
func (m *ManagerClient) Prepare(method, url string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, m.buildURI(url), body)

	if err == nil {
		r.Header.Add("User-Agent", UserAgent)
		r.Header.Add("Api-Key", m.key)
	}
	return r, err
}

// IsServerAuthEnforced returns true if server authentication is requested by the client
func (m *ManagerClient) IsServerAuthEnforced() bool {
	return m.serverKey != ""
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
				if m.serverKey == string(key) {
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
	return fmt.Sprintf("%s://%s:%s/%s", m.proto, m.host, m.port, url)
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
			return stats.Size() > m.maxUploadSize
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
			// Prepare gzip content
			body := new(bytes.Buffer)
			w := gzip.NewWriter(body)
			b, err := ioutil.ReadAll(r)
			if err != nil {
				return fmt.Errorf("PostLogs failed to prepare body")
			}
			w.Write(b)
			w.Close()

			req, err := m.Prepare("POST", PostLogsURL, bytes.NewBuffer(body.Bytes()))
			// Sending gzip data
			req.Header.Add("Accept-Encoding", "gzip")

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

// Close closes idle connections from underlying transport
func (m *ManagerClient) Close() {
	m.httpClient.CloseIdleConnections()
}
