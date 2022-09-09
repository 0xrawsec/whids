package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/0xrawsec/golog"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/api/server"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml/v2"
)

const (
	copyright = "WHIDS Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	license   = `AGPLv3: This program comes with ABSOLUTELY NO WARRANTY.`

	exitFail = 1
)

var (
	manager   *server.Manager
	osSignals = make(chan os.Signal)

	// Used for certificate generation
	defaultOrg          = "WHIDS Manager"
	defaultCertValidity = time.Hour * 24 * 365

	simpleManagerConfig = server.ManagerConfig{
		AdminAPI: server.AdminAPIConfig{
			Host: "localhost",
			Port: api.AdmAPIDefaultPort,
		},
		EndpointAPI: server.EndpointAPIConfig{
			Host: "0.0.0.0",
			Port: api.EptAPIDefaultPort,
		},
		Logging: server.ManagerLogConfig{
			Root:        "./data/logs",
			LogBasename: "forwarded",
		},
		DumpDir:  "./data/dumps",
		Database: "./data/database",
	}
)

/////////////////////////// generate_cert.go ///////////////////////////////////

func generateCert(hosts []string) (err error) {
	var key, cert []byte

	if key, cert, err = utils.GenerateCert(defaultOrg, hosts, defaultCertValidity); err != nil {
		return
	}

	if err = utils.HidsWriteData("key.pem", key); err != nil {
		return
	}

	if err = utils.HidsWriteData("cert.pem", cert); err != nil {
		return
	}

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
	repairDB    bool
	fingerprint string
	user        string
	imprules    string

	logger *golog.Logger
)

func main() {

	flag.BoolVar(&keygen, "key", keygen, "Generate a random client API key. Both client and manager configuration file will needs to be updated with it.")
	flag.BoolVar(&certgen, "certgen", certgen, "Generate a couple (key and cert) to be used for TLS connections."+
		"The certificate gets generated for the IP address specified in the configuration file.")
	flag.BoolVar(&dumpConfig, "dump-config", dumpConfig, "Dumps a skeleton of manager configuration")
	flag.BoolVar(&openapi, "openapi", openapi, "Prints JSON formatted OpenAPI definition")
	flag.BoolVar(&repairDB, "repair", repairDB, "Attempt to repair database")
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
		var key string
		var err error

		if key, err = utils.NewKey(api.DefaultKeySize); err != nil {
			logger.Abort(exitFail, "failed to generate new key:", err)
		}

		fmt.Printf("New API key: %s\n", key)
		fmt.Printf("Please manually update client and manager configuration file to make it effective\n")
		os.Exit(0)
	}

	if fingerprint != "" {
		fing, err := utils.CertFileSha256(fingerprint)
		if err != nil {
			logger.Abort(exitFail, fmt.Errorf("failed at computing fingerprint: %s", err))
		}
		fmt.Printf("Certificate fingerprint to set in client configuration to enable certificate pinning\n%s\n", fing)
		os.Exit(0)
	}

	if dumpConfig {
		enc := toml.NewEncoder(os.Stdout)
		//enc.Order(toml.OrderPreserve)
		if err := enc.Encode(simpleManagerConfig); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	if openapi {
		fmt.Println(server.OpenAPIDefinition)
		os.Exit(0)
	}

	managerConf, err := server.LoadManagerConfig(config)
	if err != nil {
		logger.Abort(exitFail, fmt.Errorf("failed to load manager configuration: %s", err))
	}

	if user != "" {

		u := &server.AdminAPIUser{
			Uuid:       utils.UUIDOrPanic().String(),
			Identifier: user,
			Key:        utils.NewKeyOrPanic(api.DefaultKeySize),
		}

		manager, err = server.NewManager(managerConf)

		if err != nil {
			logger.Abort(exitFail, fmt.Errorf("failed to create manager: %s", err))
		}

		if err = manager.CreateNewAdminAPIUser(u); err != nil {
			logger.Abort(exitFail, err)
		}

		logger.Infof("New user successfully created: %s", utils.PrettyJsonOrPanic(u))

		logger.Abort(0, "User creation: SUCCESS")
	}

	if imprules != "" {
		manager, err = server.NewManager(managerConf)
		if err != nil {
			logger.Abort(exitFail, fmt.Errorf("failed to create manager: %s", err))
		}

		if err = manager.ImportRules(imprules); err != nil {
			logger.Abort(exitFail, err)
		}

		logger.Abort(0, "Rules import: SUCCESS")
	}

	if certgen {
		err = generateCert([]string{managerConf.EndpointAPI.Host, managerConf.AdminAPI.Host})
		if err != nil {
			logger.Abort(exitFail, fmt.Errorf("failed to generate key/cert pair: %s", err))
		}
		logger.Infof("Certificate and key generated should be used for testing purposes only.")
		os.Exit(0)
	}

	managerConf.Repair = repairDB
	if repairDB {
		logger.Infof("Attempting to repair broken database")
	}

	manager, err = server.NewManager(managerConf)
	if err != nil {
		logger.Abort(exitFail, fmt.Errorf("failed to create manager: %s", err))
	}

	// Registering signal handler for sig interrupt
	signal.Notify(osSignals, os.Interrupt)
	go func() {
		<-osSignals
		logger.Infof("Received SIGINT, shutting the manager down properly")
		manager.Shutdown()
	}()
	// Running the manager
	manager.Run()
	manager.Wait()
}
