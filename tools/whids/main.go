package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"

	"github.com/0xrawsec/gene/engine"
	"golang.org/x/sys/windows/svc"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/fsutil"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/utils"
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
	license   = `License Apache 2.0: This program comes with ABSOLUTELY NO WARRANTY.`

	svcName = "WHIDS"
)

var (
	flagDumpDefault bool
	flagDryRun      bool
	flagPrintAll    bool
	debugFlag       bool
	versionFlag     bool
	flagService     bool
	flagProfile     bool

	hids *HIDS

	importRules string

	config = filepath.Join(abs, "config.json")

	osSignals = make(chan os.Signal)
)

func printInfo(writer io.Writer) {
	fmt.Fprintf(writer, "%s\nVersion: %s (commit: %s)\nCopyright: %s\nLicense: %s\n\n", banner, version, commitID, copyright, license)
}

func fmtAliases() string {
	aliases := make([]string, 0, len(channelAliases))
	for alias, channel := range channelAliases {
		aliases = append(aliases, fmt.Sprintf("\t\t%s : %s", alias, channel))
	}
	return strings.Join(aliases, "\n")
}

func runHids(service bool) {
	var err error
	var hidsConf HIDSConfig

	log.Infof("Running HIDS as Windows service: %t", service)

	hidsConf, err = LoadsHIDSConfig(config)
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Failed to load configuration: %s", err))
	}

	hids, err = NewHIDS(&hidsConf)
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Failed to create HIDS: %s", err))
	}

	hids.DryRun = flagDryRun
	hids.PrintAll = flagPrintAll

	// If not a service we need to be able to stop the HIDS
	if !service {
		// Register SIGINT handler to stop listening on channels
		signal.Notify(osSignals, os.Interrupt)
		go func() {
			<-osSignals
			log.Infof("Received SIGINT")
			// runs stop on sigint
			hids.Stop()
		}()
	}

	// Runs HIDS and wait for the output
	hids.Run()
	if !service {
		hids.Wait()
	}
}

func proctectDir(dir string) {
	var out []byte
	var err error

	// we first need to reset the ACLs otherwise next command does not work
	cmd := []string{"icacls", dir, "/reset"}
	if out, err = exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
		log.Errorf("Failed to reset installation directory ACLs: %s", err)
		log.Errorf("icacls output: %s", string(out))
		return
	}

	// we grant Administrators and SYSTEM full access rights
	cmd = []string{"icacls", dir, "/inheritance:r", "/grant:r", "Administrators:(OI)(CI)F", "/grant:r", "SYSTEM:(OI)(CI)F"}
	if out, err = exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
		log.Errorf("Failed to protect installation directory with ACLs: %s", err)
		log.Errorf("icacls output: %s", string(out))
		return
	}

	log.Infof("Successfully protected installation directory with ACLs")
}

func main() {

	flag.BoolVar(&flagDumpDefault, "dump-conf", flagDumpDefault, "Dumps default configuration")
	flag.BoolVar(&flagDryRun, "dry", flagDryRun, "Dry run (do everything except listening on channels)")
	flag.BoolVar(&flagPrintAll, "all", flagPrintAll, "Print all events passing through HIDS")
	flag.BoolVar(&versionFlag, "v", versionFlag, "Print version information and exit")
	flag.BoolVar(&flagProfile, "prof", flagProfile, "Profile program")
	flag.BoolVar(&debugFlag, "d", debugFlag, "Enable debugging messages")
	flag.StringVar(&config, "c", config, "Configuration file")
	flag.StringVar(&importRules, "import", importRules, "Import rules")

	flag.Usage = func() {
		printInfo(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\nAvailable Channel Aliases:\n%s\n", fmtAliases())
		fmt.Fprintf(os.Stderr, "\nAvailable Dump modes: %s\n", strings.Join(dumpOptions, ", "))
		flag.PrintDefaults()
	}

	flag.Parse()

	// set logfile the time the service starts
	log.SetLogfile(filepath.Join(abs, "bootstrap.log"))

	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("failed to determine if we are running in an interactive session: %v", err))
	}

	// If it is called by the Windows Service Manager (not interactive)
	if !isIntSess {
		// if running as service we protect installation directory with appropriate ACLs
		if fsutil.IsDir(abs) {
			proctectDir(abs)
		}
		runService(svcName, false)
		return
	}

	// profile the program
	if flagProfile {
		f, err := os.Create("cpu.pprof")
		if err != nil {
			log.Errorf("Failed to create profile file")
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Print version information and exit
	if versionFlag {
		printInfo(os.Stderr)
		os.Exit(exitSuccess)
	}

	if flagDumpDefault {
		fmt.Println(utils.PrettyJSON(DefaultHIDSConfig))
		os.Exit(exitSuccess)
	}

	// Enabling debug if needed
	if debugFlag {
		log.InitLogger(log.LDebug)
	}

	hidsConf, err := LoadsHIDSConfig(config)
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Failed to load configuration: %s", err))
	}

	// has to be there so that we print logs to stdout
	if importRules != "" {
		// in order not to write logs into file
		// TODO: add a stream handler to log facility
		hidsConf.Logfile = ""
		hids, err = NewHIDS(&hidsConf)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed create HIDS: %s", err))
		}
		log.Infof("Importing rules from %s", importRules)
		hids.engine = engine.NewEngine(false)
		hids.engine.SetDumpRaw(true)

		if err := hids.engine.LoadDirectory(importRules); err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to import rules: %s", err))
		}

		prules, psha256 := hids.rulesPaths()
		rules := new(bytes.Buffer)
		for rule := range hids.engine.GetRawRule(".*") {
			if _, err := rules.Write([]byte(rule + "\n")); err != nil {
				log.LogErrorAndExit(fmt.Errorf("Failed to import rules: %s", err))
			}
		}

		if err := ioutil.WriteFile(prules, rules.Bytes(), defaultPerms); err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to import rules: %s", err))
		}

		if err := ioutil.WriteFile(psha256, []byte(data.Sha256(rules.Bytes())), defaultPerms); err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to import rules: %s", err))
		}

		log.Infof("IMPORT SUCCESSFUL: %s", prules)
		os.Exit(0)
	}

	runHids(false)
	hids.LogStats()
}
