package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/fsutil/logfile"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/golang-win32/win32/wevtapi"
	"github.com/0xrawsec/whids/collector"
	"github.com/0xrawsec/whids/hooks"
	"github.com/0xrawsec/whids/utils"
)

/////////////////////////////////// Main ///////////////////////////////////////

// XMLEventToGoEvtxMap converts an XMLEvent as returned by wevtapi to a GoEvtxMap
// object that Gene can use
// TODO: Improve for more perf
func XMLEventToGoEvtxMap(xe *wevtapi.XMLEvent) (*evtx.GoEvtxMap, error) {
	ge := make(evtx.GoEvtxMap)
	bytes, err := json.Marshal(xe.ToJSONEvent())
	if err != nil {
		return &ge, err
	}
	err = json.Unmarshal(bytes, &ge)
	if err != nil {
		return &ge, err
	}
	return &ge, nil
}

/////////////////////////////////// Main ///////////////////////////////////////

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

	// Rule update constants
	geneRulesRepo = "https://github.com/0xrawsec/gene-rules/archive/master.zip"
	databaseZip   = "latest-database.zip"

	// Windows Logging constants
	winLogChannel = "Application"
	winLogSource  = "Whids"
	winLogEventID = 1337

	// Default permissions for output files
	defaultPerms = 0640

	serviceCLFlag = "service"
)

var (
	debug             bool
	trace             bool
	versionFlag       bool
	update            bool
	winLog            bool
	enDNSLog          bool
	enHooks           bool
	enCryptoProt      bool
	flagProcTermEn    bool // set the flag to true if process termination is enabled
	flagPrintAll      bool
	flagService       bool
	flagPhenix        bool
	flagDumpCompress  bool
	flagDumpEnable    bool
	flagProfile       bool
	rulesPath         string
	whitelist         string
	blacklist         string
	output            string
	logOut            string
	manager           string
	criticalityThresh int
	tags              []string
	names             []string
	listeningChannels []string
	tagsVar           args.ListVar
	namesVar          args.ListVar
	windowsChannels   args.ListVar
	timeout           args.DurationVar
	writer            io.Writer

	forwarder *collector.Forwarder

	abs, _            = filepath.Abs(filepath.Dir(os.Args[0]))
	databasePath      = filepath.Join(abs, "latest-database")
	managerRulesCache = filepath.Join(databasePath, "manager-cache.gen")
	dumpDirectory     = filepath.Join(abs, "dumps")
	dump              = "none"
	dumpOptions       = []string{"memory", "file", "all"}
	dumpTresh         = 8

	channelAliases = map[string]string{
		"sysmon":   "Microsoft-Windows-Sysmon/Operational",
		"security": "Security",
		"dns":      "Microsoft-Windows-DNS-Client/Operational",
		"ps":       "Microsoft-Windows-PowerShell/Operational",
		"all":      "All aliased channels",
	}
	ruleExts = args.ListVar{".gen", ".gene"}
	tplExt   = ".tpl"

	// Needed by Hooks
	selfGUID    = ""
	selfPath, _ = filepath.Abs(os.Args[0])
	selfPid     = os.Getpid()

	cryptoLockerFilecreateLimit = int64(50)

	fileSizeMB = int64(100)

	// Number of retries between rules updates
	dlRetries = 40

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

func allChannels() []string {
	channels := make([]string, 0, len(channelAliases))
	for alias, channel := range channelAliases {
		if alias != "all" {
			channels = append(channels, channel)
		}
	}
	return channels
}

func prepareChannels() []string {
	uniqChannels := datastructs.NewSyncedSet()
	for _, channel := range []string(windowsChannels) {
		if channel == "all" {
			allChans := allChannels()
			uniqChannels.Add(datastructs.ToInterfaceSlice(allChans)...)
		} else {
			uniqChannels.Add(channel)
		}
	}
	channels := make([]string, 0, uniqChannels.Len())
	for _, channel := range *uniqChannels.List() {
		channels = append(channels, channel.(string))
	}
	return channels
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
					if flagPhenix {
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

func gotSignaled() (bool, os.Signal) {
	select {
	case sig := <-osSignals:
		return true, sig
	default:
		return false, nil
	}
}

func main() {
	flag.Var(&windowsChannels, "c", fmt.Sprintf("Windows channels to monitor or their aliases.\n\tAvailable aliases:\n%s\n", fmtAliases()))
	flag.Var(&timeout, "timeout", "Stop working after timeout (format: 1s, 1m, 1h, 1d ...)")

	flag.BoolVar(&trace, "trace", trace, "Tells the engine to use the trace function of the rules")
	flag.BoolVar(&debug, "d", debug, "Enable debugging messages")
	flag.BoolVar(&versionFlag, "v", versionFlag, "Print version information and exit")
	flag.BoolVar(&update, "u", update, fmt.Sprintf(`Update gene database and use it in 
addition to the other rule paths (Repo: %s)`, geneRulesRepo))
	flag.BoolVar(&winLog, "winlog", winLog, fmt.Sprintf("Enable windows logging in channel %s", winLogChannel))
	flag.BoolVar(&enDNSLog, "dns", enDNSLog, "Enable DNS logging (not disabled when whids quits)")
	flag.BoolVar(&enHooks, "hooks", enHooks, `Enable Hooking functions to enrich events before they go through the engine 
When this option is enabled, DNS logging is also enabled`)
	flag.BoolVar(&enCryptoProt, "protect", enCryptoProt, "Enable basic protection against crypto lockers")
	flag.BoolVar(&flagPrintAll, "all", flagPrintAll, "Print all the events")
	flag.BoolVar(&flagService, serviceCLFlag, flagService, "Run in simple service mode (restart after child failure)")
	flag.BoolVar(&flagPhenix, "phenix", flagPhenix, "Phenix mode (i.e. never dies)")
	flag.BoolVar(&flagDumpCompress, "C", flagDumpCompress, "Enable dumped files compression")
	flag.BoolVar(&flagProfile, "prof", flagProfile, "Profile program")

	flag.StringVar(&whitelist, "wl", whitelist, "File containing values to insert into the whitelist")
	flag.StringVar(&blacklist, "bl", blacklist, "File containing values to insert into the blacklist")
	flag.StringVar(&rulesPath, "r", rulesPath, "Rule file or directory")
	flag.StringVar(&output, "o", output, "Write alerts to file instead of stdout")
	flag.StringVar(&manager, "man", manager, "Works with a manager running on a foreign server")
	flag.StringVar(&logOut, "l", logOut, "Write logs to file instead of stderr")
	flag.StringVar(&databasePath, "update-dir", databasePath, "Directory where rules will be downloaded")
	flag.StringVar(&dump, "dump", dump, fmt.Sprintf("Dumping options available through hooks. Available: %s", strings.Join(dumpOptions, ", ")))
	flag.StringVar(&dumpDirectory, "dump-dir", dumpDirectory, "Dump directory, where to dump the files collected")

	flag.IntVar(&dumpTresh, "dt", dumpTresh, "Dumping threshold file/memory only if alert is >= treshold")
	flag.IntVar(&criticalityThresh, "t", criticalityThresh, "Criticality treshold. Prints only if criticality above threshold")
	flag.IntVar(&dlRetries, "update-retries", dlRetries, "Number of retries (every 5s) when updating the rules (will retry forever if rule download path does not exist)")
	flag.Int64Var(&fileSizeMB, "size", fileSizeMB, "Maximum output file «size (in MB) before rotation")

	flag.Usage = func() {
		printInfo(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", filepath.Base(os.Args[0]))
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

	// prepare the channels and set listeningChannels
	listeningChannels = prepareChannels()

	// Print version information and exit
	if versionFlag {
		printInfo(os.Stderr)
		os.Exit(exitSuccess)
	}

	// Enabling debug if needed
	if debug {
		log.InitLogger(log.LDebug)
	}

	// Initializing the output file
	if output != "" {
		log.Infof("Writing output to: %s", output)
		var err error
		writer, err = logfile.OpenFile(output, defaultPerms, fileSizeMB*logfile.MB)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to create output file: %s", err), exitFail)
		}
	} else {
		writer = os.Stdout
	}

	// Initializing forwarder and make it run
	if manager != "" {
		var fconf collector.ForwarderConfig
		cfd, err := os.Open(manager)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to open manager configuration file: %s", err), exitFail)
		}
		b, err := ioutil.ReadAll(cfd)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to read manager configuration file: %s", err), exitFail)
		}
		err = json.Unmarshal(b, &fconf)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to parse manager configuration: %s", err), exitFail)
		}
		forwarder, err = collector.NewForwarder(&fconf)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Failed to initialize manager: %s", err), exitFail)
		}
		// Run the forwarder in a separate thread
		forwarder.Run()
		// We can close configuration file
		cfd.Close()
	}

	if logOut != "" {
		log.SetLogfile(logOut, defaultPerms)
	}

	// If we want to run it as a service
	if flagService {
		service()
		os.Exit(exitSuccess)
	} else {
		// We monitor parent process if needed
		monitorParentProcess()
	}

	// HookManager initialization
	// hooks to be applied before detection
	preDetHookMan := hooks.NewHookMan()
	// hooks to be applied post detection
	postDetHookMan := hooks.NewHookMan()

	// We enable those hooks anyway since it is needed to skip
	// events generated by WHIDS process
	preDetHookMan.Hook(hookSelfGUID, sysmonEventsWithImage)
	preDetHookMan.Hook(hookProcTerm, sysmonProcTermination)
	preDetHookMan.Hook(hookStats, statFilter)
	preDetHookMan.Hook(hookTrack, statFilter)

	// if crypto protect enabled
	if enCryptoProt {
		preDetHookMan.Hook(hookCryptoProtect, statFilter)
		preDetHookMan.Hook(hookTerminator, statFilter)
	}

	if enHooks {
		log.Info("Enabling Hooks")
		preDetHookMan.Hook(hookDNS, dnsFilter)
		preDetHookMan.Hook(hookNetConn, sysmonNetConnFilter)
		preDetHookMan.Hook(hookSetImageSize, sysmonEventsWithImage)
		preDetHookMan.Hook(hookProcessIntegrity, sysmonEventsWithImage)
		// needs DNS logs to be enabled as well
		enDNSLog = true
		switch dump {
		case "memory":
			flagDumpEnable = true
			postDetHookMan.Hook(hookDumpProcess, anySysmonEvent)
		case "file":
			flagDumpEnable = true
			postDetHookMan.Hook(hookDumpFile, anySysmonEvent)
		case "all":
			flagDumpEnable = true
			postDetHookMan.Hook(hookDumpProcess, anySysmonEvent)
			postDetHookMan.Hook(hookDumpFile, anySysmonEvent)
		}
	}

	// Create a go routine to forward automatically the dumps to the manager
	if flagDumpEnable && forwarder != nil {
		// force compression in this case
		flagDumpCompress = true
		go func() {
			for {
				for wi := range fswalker.Walk(dumpDirectory) {
					for _, fi := range wi.Files {
						sp := strings.Split(wi.Dirpath, string(os.PathSeparator))
						// dump only compressed files
						if filepath.Ext(fi.Name()) == ".gz" {
							if len(sp) >= 2 {
								fullpath := filepath.Join(wi.Dirpath, fi.Name())
								fu, err := forwarder.Client.PrepareFileUpload(fullpath, sp[len(sp)-2], sp[len(sp)-1], fi.Name())
								if err != nil {
									log.Errorf("Failed to prepare dump file to upload: %s", err)
									continue
								}
								if err := forwarder.Client.PostDump(fu); err != nil {
									log.Errorf("%s", err)
									continue
								}
								log.Infof("Dump file successfully sent to manager, deleting: %s", fullpath)
								os.Remove(fullpath)
							} else {
								log.Errorf("Unexpected directory layout, cannot send dump to manager")
							}
						}
					}
				}
				time.Sleep(60 * time.Second)
			}
		}()
	}

	if enDNSLog {
		log.Info("Enabling DNS client logging")
		err := utils.EnableDNSLogs()
		if err != nil {
			log.Errorf("Cannot enable DNS logging: %s", err)
		}
	}

	// Update Database
	if update && forwarder == nil {
		log.Infof("Downloading rules from: %s", geneRulesRepo)
		// Kind of infinite loop while databasePath does not exist
		for i := 0; i < dlRetries; {
			client := &http.Client{}
			err := utils.HTTPGet(client, geneRulesRepo, databaseZip)
			if err != nil {
				log.Errorf("Failed to download latest gene-rules: %s", err)
			} else {
				err = utils.Unzip(databaseZip, databasePath)
				if err != nil {
					log.Errorf("Could not unzip latest gene-rules: %s", err)
				}
				break
			}
			// We increment because we know that we will have rules
			// available anyway
			if fsutil.IsDir(databasePath) {
				i++
			}

			// We stop running if we got signaled
			if ok, sig := gotSignaled(); ok {
				log.Infof("Aborting, received signal: %s", sig)
				os.Exit(exitFail)
			}

			log.Info("Retrying to download rules")
			time.Sleep(5 * time.Second)
		}
		rulesPath = databasePath
	}

	// Control parameters
	if rulesPath == "" {
		//log.LogErrorAndExit(fmt.Errorf("No rule file to load"), exitFail)
		log.Warn("No rule file to load")
	}

	// Initialization
	e := engine.NewEngine(trace)
	setRuleExts := datastructs.NewSyncedSet()
	tags = []string(tagsVar)
	names = []string(namesVar)

	// Validation
	if len(tags) > 0 && len(names) > 0 {
		log.LogErrorAndExit(fmt.Errorf("Cannot search by tags and names at the same time"), exitFail)
	}
	e.SetFilters(names, tags)

	// Initializes the set of rule extensions
	for _, e := range ruleExts {
		setRuleExts.Add(e)
	}

	if forwarder == nil {
		// We have to load the containers before the rules
		// For the Whitelist
		if whitelist != "" {
			wlf, err := os.Open(whitelist)
			if err != nil {
				log.LogErrorAndExit(err, exitFail)
			}
			for line := range readers.Readlines(wlf) {
				e.Whitelist(string(line))
			}
			wlf.Close()
		}
		log.Infof("Size of whitelist container: %d", e.WhitelistLen())
		// For the Blacklist
		if blacklist != "" {
			blf, err := os.Open(blacklist)
			if err != nil {
				log.LogErrorAndExit(err, exitFail)
			}
			for line := range readers.Readlines(blf) {
				e.Blacklist(string(line))
			}
			blf.Close()
		}
		log.Infof("Size of blacklist container: %d", e.BlacklistLen())

		// Loading the rules
		e.LoadDirectory(rulesPath)
	} else {
		var rules string
		log.Infof("Loading rules available in manager")
		sha256, err := forwarder.Client.GetRulesSha256()
		if err != nil {
			log.Error(err)
			goto backup
		}
		rules, err = forwarder.Client.GetRules()
		if err != nil {
			log.Error(err)
			goto backup
		}
		if sha256 != data.Sha256([]byte(rules)) {
			log.Errorf("Failed to verify rules integrity")
			goto backup
		}
		err = e.LoadReader(bytes.NewReader([]byte(rules)))
	backup:
		if err != nil {
			log.Warnf("Cannot get rules from manager, trying to load latest rule database: %s", databasePath)
			if err := e.LoadDirectory(databasePath); err != nil {
				log.Errorf("Failed to load latest rule database: %s", err)
			}
		} else {
			if !fsutil.IsDir(databasePath) {
				if err := os.MkdirAll(databasePath, defaultPerms); err != nil {
					log.Errorf("Failed to create directory (%s): %s", databasePath, err)
				}
			}
			fd, err := os.Create(managerRulesCache)
			if err != nil {
				log.Errorf("Failed to create manager rules cache (%s): %s", managerRulesCache, err)
			} else {
				fd.WriteString(rules)
				fd.Close()
			}
		}
	}
	log.Infof("Loaded %d rules", e.Count())

	// Register a timeout if specified in Command line
	signals := make(chan bool)
	eventCnt, alertsCnt := 0, 0
	start := time.Now()
	if timeout > 0 {
		go func() {
			time.Sleep(time.Duration(timeout))
			for i := 0; i < len(listeningChannels); i++ {
				signals <- true
			}
		}()
	}

	// Register SIGINT handler to stop listening on channels
	signal.Notify(osSignals, os.Interrupt)
	go func() {
		<-osSignals
		log.Infof("Received SIGINT")
		for i := 0; i < len(listeningChannels); i++ {
			signals <- true
		}
		// Close the writer properly if not Stdout
		if l, ok := writer.(*logfile.LogFile); ok {
			l.Close()
		}
		// Close the forwarder if not nil
		if forwarder != nil {
			forwarder.Close()
		}
	}()

	// Loop starting the monitoring of the various channels
	waitGr := sync.WaitGroup{}
	winLogger, err := utils.NewWindowsLogger(winLogChannel, winLogSource)
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Cannot create windows logger: %s", err))
	}
	defer func() {
		log.Infof("Closing windows logger")
		winLogger.Close()
	}()

	for i := range listeningChannels {
		winChan := listeningChannels[i]

		// We flush DNS cache before monitoring DNS channel
		if winChan == "dns" || winChan == channelAliases["dns"] {
			log.Info("Flushing DNS Cache")
			utils.FlushDNSCache()
		}

		waitGr.Add(1)
		// New go routine per channel
		go func() {
			defer waitGr.Done()
			// Try to find an alias for the channel
			if c, ok := channelAliases[strings.ToLower(winChan)]; ok {
				winChan = c
			}
			log.Infof("Listening on Windows channel: %s", winChan)
			ec := wevtapi.GetAllEventsFromChannel(winChan, wevtapi.EvtSubscribeToFutureEvents, signals)
			for xe := range ec {
				event, err := XMLEventToGoEvtxMap(xe)
				if err != nil {
					log.Errorf("Failed to convert event: %s", err)
					log.Debugf("Error data: %v", xe)
				}
				// Place Hooks over here
				preDetHookMan.RunHooksOn(event)

				// We skip if it is one of our Event
				if isSelf(event) {
					continue
				}

				if n, crit := e.Match(event); len(n) > 0 {
					if crit >= criticalityThresh {
						switch {
						case forwarder != nil:
							forwarder.PipeEvent(event)
						case winLog:
							winLogger.Log(winLogEventID, "Warning", string(evtx.ToJSON(event)))
						default:
							fmt.Fprintf(writer, "%s\n", string(evtx.ToJSON(event)))
						}
						// Pipe the event to be sent to the forwarder
						// Run hooks post detection
						postDetHookMan.RunHooksOn(event)
						alertsCnt++
					}
				} else {
					if flagPrintAll {
						fmt.Fprintf(writer, "%s\n", string(evtx.ToJSON(event)))
					}
				}
				if w, ok := writer.(*logfile.LogFile); ok {
					w.Flush()
				}
				eventCnt++
			}
		}()
	}
	// Run bullshit command so that at least one Process Terminate
	// is generated (used to check if process termination events are enabled)
	exec.Command(os.Args[0], "-h").Start()
	waitGr.Wait()

	stop := time.Now()
	log.Infof("Count Event Scanned: %d", eventCnt)
	log.Infof("Average Event Rate: %.2f EPS", float64(eventCnt)/(stop.Sub(start).Seconds()))
	log.Infof("Alerts Reported: %d", alertsCnt)
	log.Infof("Count Rules Used (loaded + generated): %d", e.Count())
}
