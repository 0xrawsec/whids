package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hooks"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"utils"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/fsutil/logfile"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/golang-win32/win32/wevtapi"
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
	rulesPath         string
	whitelist         string
	blacklist         string
	output            string
	logOut            string
	criticalityThresh int
	tags              []string
	names             []string
	listeningChannels []string
	tagsVar           args.ListVar
	namesVar          args.ListVar
	windowsChannels   args.ListVar
	timeout           args.DurationVar
	writer            io.Writer

	abs, _       = filepath.Abs(filepath.Dir(os.Args[0]))
	databasePath = filepath.Join(abs, "latest-database")

	channelAliases = map[string]string{
		"sysmon":   "Microsoft-Windows-Sysmon/Operational",
		"security": "Security",
		"dns":      "Microsoft-Windows-DNS-Client/Operational",
		"all":      "All aliased channels",
	}
	ruleExts = args.ListVar{".gen", ".gene"}
	tplExt   = ".tpl"

	// Needed by Hooks
	selfGUID                    = ""
	selfPath, _                 = filepath.Abs(os.Args[0])
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
	upFn, upSfn := strings.ToUpper(sfn), strings.ToUpper(fn)
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
					// If we are here it means our parent service has been terminated
					// so we abourt ourself in a gentle way
					osSignals <- os.Interrupt
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}()
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
	flag.StringVar(&whitelist, "wl", whitelist, "File containing values to insert into the whitelist")
	flag.StringVar(&blacklist, "bl", blacklist, "File containing values to insert into the blacklist")
	flag.StringVar(&rulesPath, "r", rulesPath, "Rule file or directory")
	flag.StringVar(&output, "o", output, "Write alerts to file instead of stdout")
	flag.StringVar(&logOut, "l", logOut, "Write logs to file instead of stderr")
	flag.StringVar(&databasePath, "update-dir", databasePath, "Directory where rules will be downloaded")
	flag.IntVar(&criticalityThresh, "t", criticalityThresh, "Criticality treshold. Prints only if criticality above threshold")
	flag.IntVar(&dlRetries, "update-retries", dlRetries, "Number of retries (every 5s) when uploading the rules (will retry forever if rule download path does not exist)")
	flag.Int64Var(&fileSizeMB, "size", fileSizeMB, "Maximum output file size (in MB) before rotation")

	flag.Usage = func() {
		printInfo(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

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
			log.LogErrorAndExit(fmt.Errorf("Cannot create output file: %s", err), exitFail)
		}
	} else {
		writer = os.Stdout
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
	hookMan := hooks.NewHookMan()
	// We enable those hooks anyway since it is needed to skip
	// events generated by WHIDS process
	hookMan.Hook(hookSelfGUID, sysmonEventsWithImage)
	hookMan.Hook(hookProcTerm, sysmonProcTermination)
	hookMan.Hook(hookStats, statFilter)
	hookMan.Hook(hookTrack, statFilter)
	// if crypto protect enabled
	if enCryptoProt {
		hookMan.Hook(hookCryptoProtect, statFilter)
		hookMan.Hook(hookTerminator, statFilter)
	}

	if enHooks {
		log.Info("Enabling Hooks")
		hookMan.Hook(hookDNS, dnsFilter)
		hookMan.Hook(hookNetConn, sysmonNetConnFilter)
		hookMan.Hook(hookSetImageSize, sysmonEventsWithImage)
		// needs DNS logs to be enabled as well
		enDNSLog = true
	}

	if enDNSLog {
		log.Info("Enabling DNS client logging")
		err := utils.EnableDNSLogs()
		if err != nil {
			log.Errorf("Cannot enable DNS logging: %s", err)
		}
	}

	// Update Database
	if update {
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
			log.Info("Retrying to download rules update")
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

	// We have to load the containers befor the rules
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
	realPath, err := fsutil.ResolveLink(rulesPath)
	if err != nil {
		log.LogErrorAndExit(err, exitFail)
	}

	// Loading the templates first
	templateDir := realPath
	if fsutil.IsFile(realPath) {
		templateDir = filepath.Dir(realPath)
	}
	if templateDir != "" {
		for wi := range fswalker.Walk(templateDir) {
			for _, fi := range wi.Files {
				ext := filepath.Ext(fi.Name())
				templateFile := filepath.Join(wi.Dirpath, fi.Name())
				if ext == tplExt {
					log.Infof("Loading regexp templates from file: %s", templateFile)
					err := e.LoadTemplate(templateFile)
					if err != nil {
						log.Errorf("Error loading %s: %s", templateFile, err)
					}
				}
			}
		}
	}

	// Handle both rules argument as file or directory
	switch {
	case fsutil.IsFile(realPath):
		err := e.Load(realPath)
		if err != nil {
			log.Error(err)
		}
	case fsutil.IsDir(realPath):
		for wi := range fswalker.Walk(realPath) {
			for _, fi := range wi.Files {
				ext := filepath.Ext(fi.Name())
				rulefile := filepath.Join(wi.Dirpath, fi.Name())
				log.Debug(ext)
				// Check if the file extension is in the list of valid rule extension
				if setRuleExts.Contains(ext) {
					err := e.Load(rulefile)
					if err != nil {
						log.Errorf("Error loading %s: %s", rulefile, err)
					}
				}
			}
		}
	default:
		//log.LogErrorAndExit(fmt.Errorf("Cannot resolve %s to file or dir", rulesPath), exitFail)
	}
	log.Infof("Loaded %d rules", e.Count())

	// Register a timeout if specified in Command line
	signals := make(chan bool)
	eventCnt, alertsCnt := 0, 0
	start := time.Now()
	if timeout > 0 {
		go func() {
			time.Sleep(time.Duration(timeout))
			for _ = range []string(windowsChannels) {
				signals <- true
			}
		}()
	}

	signal.Notify(osSignals, os.Interrupt)
	go func() {
		<-osSignals
		for _ = range []string(listeningChannels) {
			signals <- true
		}
		// Close the writer properly if not Stdout
		if l, ok := writer.(*logfile.LogFile); ok {
			l.Close()
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
				hookMan.RunHooksOn(event)

				// We skip if it is one of our Event
				if isSelf(event) {
					continue
				}

				if n, crit := e.Match(event); len(n) > 0 {
					if crit >= criticalityThresh {
						fmt.Fprintf(writer, "%s\n", string(evtx.ToJSON(event)))
						if winLog {
							winLogger.Log(winLogEventID, "Warning", string(evtx.ToJSON(event)))
						}
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
