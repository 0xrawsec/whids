package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml"
)

const (
	copyright = "WHIDS Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	license   = `License Apache 2.0: This program comes with ABSOLUTELY NO WARRANTY.`

	exitFail = 1
)

var (
	managerConf api.ManagerConfig
	manager     *api.Manager
	osSignals   = make(chan os.Signal)

	// Used for certificate generation
	defaultOrg          = "WHIDS Manager"
	defaultCertValidity = time.Hour * 24 * 365

	simpleManagerConfig = api.ManagerConfig{
		AdminAPI: api.AdminAPIConfig{
			Host: "localhost",
			Port: api.AdmAPIDefaultPort,
		},
		EndpointAPI: api.EndpointAPIConfig{
			Host: "0.0.0.0",
			Port: api.EptAPIDefaultPort,
		},
		Logging: api.ManagerLogConfig{
			Root:        "./data/logs",
			LogBasename: "forwarded",
		},
		DumpDir:  "./data/dumps",
		Database: "./data/database",
	}
)

/////////////////////////// generate_cert.go ///////////////////////////////////
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

func generateCert(hosts []string) error {
	if len(hosts) == 0 {
		return fmt.Errorf("Missing required --host parameter")
	}

	var priv interface{}
	var err error

	// generate RSA key
	priv, err = rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return fmt.Errorf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(defaultCertValidity)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{defaultOrg},
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
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	certOut, err := os.OpenFile("cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %s", err)
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	certOut.Close()

	log.Info("Written cert.pem")

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %s", err)
	}

	pem.Encode(keyOut, pemBlockForKey(priv))

	keyOut.Close()

	log.Info("Written key.pem")
	return nil
}

func computeFingerprint(certPath string) (fingerprint string, err error) {
	pemBytes, err := ioutil.ReadFile(certPath)
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

func printInfo(writer io.Writer) {
	fmt.Fprintf(writer, "Version: %s (commit: %s)\nCopyright: %s\nLicense: %s\n\n", version, commitID, copyright, license)
}

var (
	keygen      bool
	certgen     bool
	dumpConfig  bool
	openapi     bool
	fingerprint string
	user        string
	imprules    string
)

func main() {

	flag.BoolVar(&keygen, "key", keygen, "Generate a random client API key. Both client and manager configuration file will needs to be updated with it.")
	flag.BoolVar(&certgen, "certgen", certgen, "Generate a couple (key and cert) to be used for TLS connections."+
		"The certificate gets generated for the IP address specified in the configuration file.")
	flag.BoolVar(&dumpConfig, "dump-config", dumpConfig, "Dumps a skeleton of manager configuration")
	flag.BoolVar(&openapi, "openapi", openapi, "Prints JSON formatted OpenAPI definition")
	flag.StringVar(&fingerprint, "fingerprint", fingerprint, "Retrieve fingerprint of certificate to set in client configuration")
	flag.StringVar(&user, "user", user, "Creates a new user")
	flag.StringVar(&imprules, "import", imprules, "Import Gene rules from a directory")

	flag.Usage = func() {
		printInfo(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] CONFIG_FILE\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	config := flag.Arg(0)

	if keygen {
		key := api.KeyGen(api.DefaultKeySize)
		fmt.Printf("New API key: %s\n", key)
		fmt.Printf("Please manually update client and manager configuration file to make it effective\n")
		os.Exit(0)
	}

	if fingerprint != "" {
		fing, err := computeFingerprint(fingerprint)
		if err != nil {
			log.Abort(exitFail, fmt.Errorf("Failed at computing fingerprint: %s", err))
		}
		fmt.Printf("Certificate fingerprint to set in client configuration to enable certificate pinning\n%s\n", fing)
		os.Exit(0)
	}

	if dumpConfig {
		enc := toml.NewEncoder(os.Stdout)
		enc.Order(toml.OrderPreserve)
		if err := enc.Encode(simpleManagerConfig); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	if openapi {
		fmt.Println(api.OpenAPIDefinition)
		os.Exit(0)
	}

	managerConf, err := api.LoadManagerConfig(config)
	if err != nil {
		log.Abort(exitFail, fmt.Errorf("Failed to load manager configuration: %s", err))
	}

	if user != "" {
		u := &api.AdminAPIUser{
			Uuid:       api.UUIDGen().String(),
			Identifier: user,
			Key:        api.KeyGen(api.DefaultKeySize),
		}

		manager, err = api.NewManager(managerConf)
		if err != nil {
			log.Abort(exitFail, fmt.Errorf("Failed to create manager: %s", err))
		}

		if err = manager.CreateNewAdminAPIUser(u); err != nil {
			log.Abort(exitFail, err)
		}

		log.Infof("New user successfully created: %s", utils.PrettyJson(u))

		log.Abort(0, "User creation: SUCCESS")
	}

	if imprules != "" {
		manager, err = api.NewManager(managerConf)
		if err != nil {
			log.Abort(exitFail, fmt.Errorf("Failed to create manager: %s", err))
		}

		if err = manager.ImportRules(imprules); err != nil {
			log.Abort(exitFail, err)
		}

		log.Abort(0, "Rules import: SUCCESS")
	}

	if certgen {
		err = generateCert([]string{managerConf.EndpointAPI.Host, managerConf.AdminAPI.Host})
		if err != nil {
			log.Abort(exitFail, fmt.Errorf("Failed to generate key/cert pair: %s", err))
		}
		log.Infof("Certificate and key generated should be used for testing purposes only.")
		os.Exit(0)
	}

	manager, err = api.NewManager(managerConf)
	if err != nil {
		log.Abort(exitFail, fmt.Errorf("Failed to create manager: %s", err))
	}

	// Registering signal handler for sig interrupt
	signal.Notify(osSignals, os.Interrupt)
	go func() {
		<-osSignals
		log.Infof("Received SIGINT, shutting the manager down properly")
		manager.Shutdown()
	}()
	// Running the manager
	manager.Run()
	manager.Wait()
}
