package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golog"
	"github.com/0xrawsec/whids/agent"
	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/agent/sysinfo"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/windows/svc"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/fsutil"
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

	configFile  = filepath.Join(abs, "config.toml")
	logFallback = filepath.Join(abs, "fallback.log")

	osSignals = make(chan os.Signal)

	logger = golog.Stdout
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
	//enc.Order(toml.OrderPreserve)
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

func restoreAuditPolicies(c *config.Agent) {
	// Removing ACLs found in config
	logger.Infof("Restoring global File System Audit ACLs")
	ac := c.AuditConfig
	for _, ap := range ac.AuditPolicies {
		if err := utils.DisableAuditPolicy(ap); err != nil {
			logger.Errorf("Failed to disable audit policy %s: %s", ap, err)
		}
	}

	dirs := utils.StdDirs(utils.ExpandEnvs(ac.AuditDirs...)...)
	if err := utils.RemoveEDRAuditACL(dirs...); err != nil {
		logger.Errorf("Error while restoring File System Audit ACLs: %s", err)
	}

	if err := c.CanariesConfig.RestoreACLs(); err != nil {
		logger.Errorf("failed to restore canary files ACL: %s", err)
	}
}

func cleanCanaries(c *config.Agent) {
	logger.Infof("Restoring canary File System Audit ACLs")
	if err := c.CanariesConfig.RestoreACLs(); err != nil {
		logger.Errorf("errore restoring canary files ACL: %s", err)
	}

	logger.Infof("Deleting canary files")
	if err := c.CanariesConfig.Clean(); err != nil {
		logger.Errorf("error deleting canary files: %s", err)
	}
}

func deleteAutologger() error {
	return config.Autologger.Delete()
}

func runHids(service bool) {
	var err error
	var hidsConf config.Agent

	logger.Infof("Running HIDS as Windows service: %t", service)

	hidsConf, err = config.LoadAgentConfig(configFile)
	if err != nil {
		logger.Abort(exitFail, fmt.Errorf("failed to load configuration: %s", err))
	}

	edrAgent, err = agent.NewAgent(&hidsConf)
	if err != nil {
		logger.Abort(exitFail, fmt.Errorf("failed to create HIDS: %s", err))
	}

	edrAgent.DryRun = flagDryRun
	edrAgent.PrintAll = flagPrintAll

	// If not a service we need to be able to stop the HIDS
	if !service {
		// Register SIGINT handler to stop listening on channels
		signal.Notify(osSignals, os.Interrupt)
		go func() {
			<-osSignals
			logger.Infof("Received SIGINT")
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
		logger.Errorf("failed to reset installation directory ACLs: %s", err)
		logger.Errorf("icacls output: %s", string(out))
		return
	}

	// we grant Administrators and SYSTEM full access rights
	cmd = []string{"icacls", dir, "/inheritance:r", "/grant:r", "Administrators:(OI)(CI)F", "/grant:r", "SYSTEM:(OI)(CI)F"}
	if out, err = exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
		logger.Errorf("failed to protect installation directory with ACLs: %s", err)
		logger.Errorf("icacls output: %s", string(out))
		return
	}

	logger.Infof("Successfully protected installation directory with ACLs")
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
		logger.Abort(exitFail, fmt.Errorf("failed to determine if we are running in an interactive session: %v", err))
	}

	if flagInstall || flagAutologger {

		// Only when installing
		if flagInstall {
			// dump configuration first as config is needed
			// by subsequent functions
			if err := configure(); err != nil {
				logger.Errorf("failed to build configuration: %s", err)
				os.Exit(exitFail)
			}
		}

		conf, err := config.LoadAgentConfig(configFile)
		if err != nil {
			logger.Errorf("failed to load configuration: %s", err)
			os.Exit(exitFail)
		}

		if err := deleteAutologger(); err != nil {
			logger.Errorf("failed to delete autologger: %s", err)
			// do not exit as autologger might not be existing but still report error
			//os.Exit(exitFail)
		}

		if err := updateAutologger(&conf); err != nil {
			logger.Errorf("failed to update autologger: %s", err)
			os.Exit(exitFail)
		}

		os.Exit(exitSuccess)
	}

	if flagUninstall {
		// we should not abort uninstallation if error
		var conf config.Agent

		rc := exitSuccess

		if conf, err = config.LoadAgentConfig(configFile); err == nil {
			// ToDo return error and set rc accordingly
			cleanCanaries(&conf)
			restoreAuditPolicies(&conf)
		} else {
			logger.Errorf("failed to load configuration: %s", err)
			rc = exitFail
		}

		if err := deleteAutologger(); err != nil {
			logger.Errorf("failed to delete autologger: %s", err)
			rc = exitFail
		}

		os.Exit(rc)
	}

	// profile the program
	if flagProfile {
		go func() {
			logger.Info("Running profiling server", http.ListenAndServe("0.0.0.0:4242", nil))
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
		//enc.Order(toml.OrderPreserve)
		if err := enc.Encode(DefaultHIDSConfig); err != nil {
			logger.Abort(exitFail, err)
		}
		os.Exit(exitSuccess)
	}

	// Enabling debug if needed
	if flagDebug {
		logger.Level = golog.LevelDebug
	}

	agentCfg, err := config.LoadAgentConfig(configFile)
	if err != nil {
		logger.Abort(exitFail, fmt.Sprintf("failed to load configuration: %s", err))
	}

	if flagRestore {
		restoreAuditPolicies(&agentCfg)
		os.Exit(exitSuccess)
	}

	// has to be there so that we print logs to stdout
	if importRules != "" {
		// in order not to write logs into file
		// TODO: add a stream handler to log facility
		agentCfg.Logfile = ""
		logger.Infof("Importing rules from %s", importRules)
		eng := engine.NewEngine()
		eng.SetDumpRaw(true)

		if err := eng.LoadDirectory(importRules); err != nil {
			logger.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
		}

		prules, psha256 := agentCfg.RulesConfig.RulesPaths()
		rules := new(bytes.Buffer)
		for rule := range eng.GetRawRule(".*") {
			if _, err := rules.Write([]byte(rule + "\n")); err != nil {
				logger.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
			}
		}

		if err := os.WriteFile(prules, rules.Bytes(), utils.DefaultFileModeFile); err != nil {
			logger.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
		}

		if err := os.WriteFile(psha256, []byte(data.Sha256(rules.Bytes())), utils.DefaultFileModeFile); err != nil {
			logger.Abort(exitFail, fmt.Sprintf("failed to import rules: %s", err))
		}

		logger.Infof("IMPORT SUCCESSFUL: %s", prules)
		os.Exit(0)
	}

	// if we run from command line (interactive session)
	if isIntSess {
		runHids(false)
		edrAgent.LogStats()
		return
	}

	// if it is called by the Windows Service Manager (not interactive)

	// set logfile the time the service starts
	if agentCfg.Logfile != "" {
		if logger, err = golog.FromPath(agentCfg.Logfile, utils.DefaultFileModeFile); err != nil {
			golog.Stdout.Error("failed to open logfile", agentCfg.Logfile, err)
		}
	}

	// if we failed at opening logfile configured
	if logger == nil {
		if logger, err = golog.FromPath(logFallback, utils.DefaultFileModeFile); err != nil {
			golog.Stdout.Error("failed to open logfile", err)
			logger = golog.Stdout
		}
	}

	// if running as service we protect installation directory with appropriate ACLs
	if fsutil.IsDir(abs) {
		proctectDir(abs)
	}

	runService(svcName, false)

}
