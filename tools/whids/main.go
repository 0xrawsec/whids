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
	"syscall"
	"time"

	"github.com/0xrawsec/gene/engine"

	"github.com/0xrawsec/golang-utils/crypto/data"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
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

	serviceCLFlag = "service"
)

var (
	flagDumpDefault bool
	flagDryRun      bool
	flagPrintAll    bool
	debug           bool
	versionFlag     bool
	flagService     bool
	flagZombie      bool
	flagProfile     bool

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

func service() {
	path := os.Args[0]
	args := os.Args[1:]
	for i, a := range args {
		if a == fmt.Sprintf("-%s", serviceCLFlag) {
			if i != len(args)-1 {
				args = append(args[:i], args[i+1:]...)
			} else {
				args = args[:i]
			}
		}
	}

	osSignals := make(chan os.Signal)
	signal.Notify(osSignals, os.Interrupt, os.Kill)
	go func() {
		<-osSignals
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()

	for {
		cmd := exec.Command(path, args...)
		log.Infof("Running: %s %s", path, strings.Join(args, " "))
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		log.Errorf("Process stopped running: %s", err)
	}
}

func monitorParentProcess() {
	var ppid int
	tmpPpid := syscall.Getppid()
	fn, err := kernel32.GetModuleFilenameFromPID(tmpPpid)
	if err != nil {
		log.Errorf("Cannot get parent Image: %s", err)
	}
	sfn, err := kernel32.GetModuleFilenameSelf()
	if err != nil {
		log.Errorf("Cannot get self module filename: %s", err)
	}
	log.Infof("Parent Process Image: %s", fn)
	log.Infof("Process Image: %s", sfn)
	upFn, upSfn := strings.ToUpper(fn), strings.ToUpper(sfn)
	if upSfn == upFn {
		// We are a child of whids so running as service
		ppid = tmpPpid
		go func() {
			for {
				fn, _ := kernel32.GetModuleFilenameFromPID(ppid)
				sfn, err := kernel32.GetModuleFilenameSelf()
				upFn, upSfn := strings.ToUpper(sfn), strings.ToUpper(fn)
				if err != nil {
					log.Errorf("Cannot get self module filename: %s", err)
				}
				if upSfn != upFn {
					// If we want Whids to reborn
					if flagZombie {
						// service option
						args := []string{fmt.Sprintf("-%s", serviceCLFlag)}
						if len(os.Args) > 1 {
							args = append(args, os.Args[1:]...)
						}
						cmd := exec.Command(os.Args[0], args...)
						log.Infof("Manager has been terminated, restarting it")
						cmd.Start()
					}
					osSignals <- os.Interrupt
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}
}

func main() {

	flag.BoolVar(&flagDumpDefault, "dump-conf", flagDumpDefault, "Dumps default configuration")
	flag.BoolVar(&flagDryRun, "dry", flagDryRun, "Dry run (do everything except listening on channels)")
	flag.BoolVar(&flagPrintAll, "all", flagPrintAll, "Print all events passing through HIDS")
	flag.BoolVar(&flagService, serviceCLFlag, flagService, "Run in simple service mode (restart after child failure)")
	flag.BoolVar(&flagZombie, "z", flagZombie, "Zombie mode (i.e. never dies)")
	flag.BoolVar(&versionFlag, "v", versionFlag, "Print version information and exit")
	flag.BoolVar(&flagProfile, "prof", flagProfile, "Profile program")
	flag.BoolVar(&debug, "d", debug, "Enable debugging messages")
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
	if debug {
		log.InitLogger(log.LDebug)
	}

	// If we want to run it as a service
	if flagService {
		service()
		os.Exit(exitSuccess)
	} else {
		// We monitor parent process if needed
		monitorParentProcess()
	}

	hidsConf, err := LoadsHIDSConfig(config)
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Failed to load configuration: %s", err))
	}

	// has to be there so that we print logs to stdout
	if importRules != "" {
		// in order not to write logs into file
		// TODO: add a add stream handler to log facility
		hidsConf.Logfile = ""
		hids, err := NewHIDS(&hidsConf)
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

	hids, err := NewHIDS(&hidsConf)
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Failed create HIDS: %s", err))
	}

	hids.DryRun = flagDryRun
	hids.PrintAll = flagPrintAll

	// Go routine to archive old logfiles
	go func() {
		hids.forwarder.ArchiveLogs()
	}()

	// Register SIGINT handler to stop listening on channels
	signal.Notify(osSignals, os.Interrupt)
	go func() {
		<-osSignals
		log.Infof("Received SIGINT")
		// runs stop on sigint
		hids.Stop()
	}()

	// Runs HIDS and wait for the output
	hids.Run()

	hids.LogStats()
}
