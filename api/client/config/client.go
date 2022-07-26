package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
)

// Client structure definition
type Client struct {
	Proto             string `toml:"proto" comment:"Protocol to use to connect to manager (http or https)"`
	Host              string `toml:"host" comment:"Hostname or IP of the manager"`
	Port              int    `toml:"port" comment:"Port at which endpoint API is running on manager server"`
	UUID              string `toml:"endpoint-uuid" comment:"Endpoint UUID configured on manager used to authenticate this endpoint"`
	Key               string `toml:"endpoint-key" comment:"Endpoint key configured on manager used to authenticate this endpoint"`
	ServerKey         string `toml:"server-key" comment:"Key configured on manager, used to authenticate server on this endpoint\n This settings does not protect from MITM, so configuring server\n certificate pinning is recommended."`
	ServerFingerprint string `toml:"server-fingerprint" comment:"Configure manager certificate pinning\n Put here the manager's certificate fingerprint"`
	Unsafe            bool   `toml:"unsafe" comment:"Allow unsafe HTTPS connection"`
	MaxUploadSize     int64  `toml:"max-upload-size" comment:"Maximum allowed upload size"`

	localAddr string
}

// ManagerIP returns the IP address of the manager if any, returns nil otherwise
func (c *Client) ManagerIP() net.IP {
	if ip := net.ParseIP(c.Host); ip != nil {
		return ip
	}

	if ips, err := net.LookupIP(c.Host); err == nil {
		return ips[0]
	}

	return nil
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (con net.Conn, err error) {
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	con, err = dialer.DialContext(ctx, network, addr)

	if err == nil && con != nil {
		if addr, ok := con.LocalAddr().(*net.TCPAddr); ok {
			c.localAddr = addr.IP.String()
		}
	}

	return
}

func (c *Client) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	con, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: c.Unsafe})

	if err != nil {
		return con, err
	}

	if con != nil {
		if addr, ok := con.LocalAddr().(*net.TCPAddr); ok {
			c.localAddr = addr.IP.String()
		}
	}

	if c.ServerFingerprint == "" {
		return con, err
	}

	connstate := con.ConnectionState()
	for _, peercert := range connstate.PeerCertificates {
		der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		hash := data.Sha256(der)
		if err != nil {
			return con, err
		}

		if hash == c.ServerFingerprint {
			return con, err
		}
	}
	return con, fmt.Errorf("server fingerprint not verified")
}

// Transport creates an approriate HTTP transport from a configuration
// Cert pinning inspired by: https://medium.com/@zmanian/server-public-key-pinning-in-go-7a57bbe39438
func (c *Client) Transport() http.RoundTripper {
	return &http.Transport{
		Proxy: nil,
		/*DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,*/
		DialContext:           c.DialContext,
		DialTLSContext:        c.DialTLSContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (c *Client) LocalAddr() string {
	return c.localAddr
}
