package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/whids/agent"
	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/agent/sysinfo"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml"
	"golang.org/x/sys/windows/svc"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/fsutil"

	"github.com/0xrawsec/golang-utils/log"
)

const (
	exitFail    = 1
	exitSuccess = 0
	banner      = `
	██╗    ██╗██╗  ██╗██╗██████╗ ███████╗
	██║    ██║██║  ██║██║██╔══██╗██╔════╝
	██║ █╗ ██║███████║██║██║  ██║███████╗
	██║███╗██║██╔══██║██║██║  ██║╚════██║
	╚███╔███╔╝██║  ██║██║██████╔╝███████║
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝
	           Windows Host IDS
	`
	copyright = "WHIDS Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	license   = `AGPLv3: This program comes with ABSOLUTELY NO WARRANTY.`

	svcName = "WHIDS"
)

var (
	abs, _ = filepath.Abs(filepath.Dir(os.Args[0]))

	// DefaultHIDSConfig is the default HIDS configuration
	DefaultHIDSConfig = agent.BuildDefaultConfig(abs)
)

var (
	flagDumpConfig bool
	flagConfigure  bool
	flagInstall    bool
	flagUninstall  bool
	flagDryRun     bool
	flagPrintAll   bool
	flagDebug      bool
	flagVersion    bool
	flagProfile    bool
	flagRestore    bool
	flagAutologger bool

	edrAgent *agent.Agent

	importRules string

	configFile = filepath.Join(abs, "config.toml")

	osSignals = make(chan os.Signal)
)

func printInfo(writer io.Writer) {
	fmt.Fprintf(writer, "%s\nVersion: %s (commit: %s)\nCopyright: %s\nLicense: %s\n\n", banner, version, commitID, copyright, license)
}

func configure() error {
	var writer *os.File
	var err error

	if writer, err = utils.HidsCreateFile(configFile); err != nil {
		return err
	}
	defer writer.Close()

	enc := toml.NewEncoder(writer)
	enc.Order(toml.OrderPreserve)
	if err := enc.Encode(DefaultHIDSConfig); err != nil {
		return err
	}
	return nil
}

func updateAutologger(c *config.Agent) error {
	if err := c.EtwConfig.ConfigureAutologger(); err != nil {
		return err
	}
	return nil
}

func restoreCanaries(c *config.Agent) {
	// Removing ACLs found in config
	log.Infof("Restoring global File System Audit ACLs")
	c.AuditConfig.Restore()

	log.Infof("Restoring canary File System Audit ACLs")
	c.CanariesConfig.RestoreACLs()
}

func cleanCanaries(c *config.Agent) {
	restoreCanaries(c)

	log.Infof("Deleting canary files")
	c.CanariesConfig.Clean()
}

func deleteAutologger() error {
	return config.Autologger.Delete()
}

func runHids(service bool) {
	var err error
	var hidsConf config.Agent

	log.Infof("Running HIDS as Windows service: %t", service)

	hidsConf, err = config.LoadAgentConfig(configFile)
	if err != nil {
		log.Abort(exitFail, fmt.Errorf("failed to load configuration: %s", err))
	}

	edrAgent, err = agent.NewAgent(&hidsConf)
	if err != nil {
		log.Abort(exitFail, fmt.Errorf("failed to create HIDS: %s", err))
	}

	edrAgent.DryRun = flagDryRun
	edrAgent.PrintAll = flagPrintAll

	// If not a service we need to be able to stop the HIDS
	if !service {
		// Register SIGINT handler to stop listening on channels
		signal.Notify(osSignals, os.Interrupt)
		go func() {
			<-osSignals
			log.Infof("Received SIGINT")
			// runs stop on sigint
			edrAgent.Stop()
		}()
	}

	// Runs HIDS and wait for the output
	edrAgent.Run()
	if !service {
		edrAgent.Wait()
	}
}

func proctectDir(dir string) {
	var out []byte
	var err error

	// we first need to reset the ACLs otherwise next command does not work
	cmd := []string{"icacls", dir, "/reset"}
	if out, err = exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
		log.Errorf("failed to reset installation directory ACLs: %s", err)
		log.Errorf("icacls output: %s", string(out))
		return
	}

	// we grant Administrators and SYSTEM full access rights
	cmd = []string{"icacls", dir, "/inheritance:r", "/grant:r", "Administrators:(OI)(CI)F", "/grant:r", "SYSTEM:(OI)(CI)F"}
	if out, err = exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
		log.Errorf("failed to protect installation directory with ACLs: %s", err)
		log.Errorf("icacls output: %s", string(out))
		return
	}

	log.Infof("Successfully protected installation directory with ACLs")
}

func main() {

	flag.BoolVar(&flagDumpConfig, "dump-conf", flagDumpConfig, "Dumps default configuration to stdout")
	flag.BoolVar(&flagInstall, "install", flagInstall, "Install EDR")
	flag.BoolVar(&flagAutologger, "autologger", flagAutologger, "Update EDR's ETW autologger configuration")
	flag.BoolVar(&flagUninstall, "uninstall", flagUninstall, "Uninstall EDR")
	flag.BoolVar(&flagDryRun, "dry", flagDryRun, "Dry run (do everything except listening on channels)")
	flag.BoolVar(&flagPrintAll, "all", flagPrintAll, "Print all events passing through HIDS")
	flag.BoolVar(&flagVersion, "v", flagVersion, "Print version information and exit")
	flag.BoolVar(&flagProfile, "prof", flagProfile, "Profile program")
	flag.BoolVar(&flagDebug, "d", flagDebug, "Enable debugging messages")
	flag.BoolVar(&flagRestore, "restore", flagRestore, "Restore Audit Policies and File System Audit ACLs according to configuration file")
	flag.StringVar(&configFile, "c", configFile, "Configuration file")
	flag.StringVar(&importRules, "import", importRules, "Import rules")

	flag.Usage = func() {
		printInfo(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(exitSuccess)
	}

	flag.Parse()

	// registering EdrInfo to make version info available from APIs
	i := &sysinfo.EdrInfo{
		Version: version,
		Commit:  commitID,
	}

	sysinfo.RegisterEdrInfo(i)

	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Abort(exitFail, fmt.Errorf("failed to determine if we are running in an interactive session: %v", err))
	}

	if flagInstall || flagAutologger {

		// Only when installing
		if flagInstall {
			// dump configuration first as config is needed
			// by subsequent functions
			if err := configure(); err != nil {
				log.Errorf("failed to build configuration: %s", err)
				os.Exit(exitFail)
			}
		}

		conf, err := config.LoadAgentConfig(configFile)
		if err != nil {
			log.Errorf("failed to load configuration: %s", err)
			os.Exit(exitFail)
		}

		if err := deleteAutologger(); err != nil {
			log.Errorf("failed to delete autologger: %s", err)
			// do not exit as autologger might not be existing but still report error
			//os.Exit(exitFail)
		}

		if err := updateAutologger(&conf); err != nil {
			log.Errorf("failed to update autologger: %s", err)
			os.Exit(exitFail)
		}

		os.Exit(exitSuccess)
	}

	if flagUninstall {
		// we should not abort uninstallation if error
		var conf config.Agent

		rc := exitSuccess

		if conf, err = config.LoadAgentConfig(configFile); err == nil {
			cleanCanaries(&conf)
		} else {
			log.Errorf("failed to load configuration: %s", err)
			rc = exitFail
		}

		if err := deleteAutologger(); err != nil {
			log.Errorf("failed to delete autologger: %s", err)
			rc = exitFail
		}

		os.Exit(rc)
	}

	// profile the program
	if flagProfile {
		go func() {
			log.Info("Running profiling server", http.ListenAndServe("0.0.0.0:4242", nil))
		}()
	}

	// Print version information and exit
	if flagVersion {
		printInfo(os.Stderr)
		os.Exit(exitSuccess)
	}

	if flagDumpConfig || flagConfigure {
		writer := os.Stdout
		enc := toml.NewEncoder(writer)
		enc.Order(toml.OrderPreserve)
		if err := enc.Encode(DefaultHIDSConfig); err != nil {
			log.Abort(exitFail, err)
		}
		os.Exit(exitSuccess)
	}

	// Enabling debug if needed
	if flagDebug {
		log.InitLogger(log.LDebug)
	}

	hidsConf, err := config.LoadAgentConfig(configFile)
	if err != nil {
		log.Abort(exitFail, fmt.Sprintf("failed to load configuration: %s", err))
	}

	if flagRestore {
		restoreCanaries(&hidsConf)
		os.Exit(exitSuccess)
	}

	// has to be there so that we print logs to stdout
	if importRules != "" {
		// in order not to write logs into file
		// TODO: add a stream handler to log facility
		hidsConf.Logfile = ""
		log.Infof("Importing rules from %s", importRules)
		eng := engine.NewEngine()
		eng.SetDumpRaw(true)

		if err := eng.LoadDirectory(importRules); err != nil {
			log.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
		}

		prules, psha256 := hidsConf.RulesConfig.RulesPaths()
		rules := new(bytes.Buffer)
		for rule := range eng.GetRawRule(".*") {
			if _, err := rules.Write([]byte(rule + "\n")); err != nil {
				log.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
			}
		}

		if err := ioutil.WriteFile(prules, rules.Bytes(), utils.DefaultPerms); err != nil {
			log.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
		}

		if err := ioutil.WriteFile(psha256, []byte(data.Sha256(rules.Bytes())), utils.DefaultPerms); err != nil {
			log.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
		}

		log.Infof("IMPORT SUCCESSFUL: %s", prules)
		os.Exit(0)
	}

	// If it is called by the Windows Service Manager (not interactive)
	if !isIntSess {
		// set logfile the time the service starts
		log.SetLogfile(filepath.Join(abs, "bootstrap.log"))

		// if running as service we protect installation directory with appropriate ACLs
		if fsutil.IsDir(abs) {
			proctectDir(abs)
		}
		runService(svcName, false)
		return
	} else {
		runHids(false)
		edrAgent.LogStats()
	}
}
