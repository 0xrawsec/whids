package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func GenerateCert(org string, hosts []string, validity time.Duration) (key, cert []byte, err error) {
	var priv interface{}

	if len(hosts) == 0 {
		err = fmt.Errorf("no host specified")
		return
	}

	// generate RSA key
	priv, err = rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		err = fmt.Errorf("failed to generate private key: %s", err)
		return
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		err = fmt.Errorf("failed to generate serial number: %s", err)
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)

	if err != nil {
		err = fmt.Errorf("failed to create certificate: %s", err)
		return
	}

	certOut := new(bytes.Buffer)

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return
	}

	cert = certOut.Bytes()

	keyOut := new(bytes.Buffer)

	if err = pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		return
	}

	key = keyOut.Bytes()

	return
}

func CertFileSha256(certPath string) (fingerprint string, err error) {
	var certFd *os.File

	if certFd, err = os.Open(certPath); err != nil {
		return
	}
	defer certFd.Close()

	fingerprint, err = CertSha256(certFd)
	return
}

func CertSha256(r io.Reader) (fingerprint string, err error) {
	pemBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return
	}

	block, _ := pem.Decode(pemBytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}

	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return
	}
	fingerprint = data.Sha256(der)
	return
}
