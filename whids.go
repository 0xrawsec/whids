package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"utils"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
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
	version   = "1.2"
	copyright = "WHIDS Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	license   = `License Apache 2.0: This program comes with ABSOLUTELY NO WARRANTY.`

	// Rule update constants
	geneRulesRepo = "https://github.com/0xrawsec/gene-rules/archive/master.zip"
	databaseZip   = "latest-database.zip"
	databasePath  = "latest-database"

	// Windows Logging constants
	winLogChannel = "Application"
	winLogSource  = "Whids"
	winLogEventID = 1337
)

var (
	debug             bool
	trace             bool
	versionFlag       bool
	update            bool
	winLog            bool
	enDNSLog          bool
	rulesPath         string
	whitelist         string
	blacklist         string
	criticalityThresh int
	tags              []string
	names             []string
	listeningChannels []string
	tagsVar           args.ListVar
	namesVar          args.ListVar
	windowsChannels   args.ListVar
	timeout           args.DurationVar
	channelAliases    = map[string]string{
		"sysmon":   "Microsoft-Windows-Sysmon/Operational",
		"security": "Security",
		"dns":      "Microsoft-Windows-DNS-Client/Operational",
		"all":      "All aliased channels",
	}
	ruleExts = args.ListVar{".gen", ".gene"}
	tplExt   = ".tpl"
)

func printInfo(writer io.Writer) {
	fmt.Fprintf(writer, "%s\nVersion: %s\nCopyright: %s\nLicense: %s\n\n", banner, version, copyright, license)
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
	log.Infof("%v", channels)
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

func main() {
	flag.Var(&windowsChannels, "c", fmt.Sprintf("Windows channels to monitor or their aliases.\n\tAvailable aliases:\n%s\n", fmtAliases()))
	flag.Var(&timeout, "timeout", "Stop working after timeout (format: 1s, 1m, 1h, 1d ...)")
	flag.BoolVar(&trace, "trace", trace, "Tells the engine to use the trace function of the rules")
	flag.BoolVar(&debug, "d", debug, "Enable debugging messages")
	flag.BoolVar(&versionFlag, "v", versionFlag, "Print version information and exit")
	flag.BoolVar(&update, "u", update, fmt.Sprintf("Update gene database and use it in addition to the other rule paths (Repo: %s)", geneRulesRepo))
	flag.BoolVar(&winLog, "winlog", winLog, fmt.Sprintf("Enable windows logging in channel %s", winLogChannel))
	flag.BoolVar(&enDNSLog, "dns", enDNSLog, "Enable DNS logging (not disabled when whids quits)")
	flag.StringVar(&whitelist, "wl", whitelist, "File containing values to insert into the whitelist")
	flag.StringVar(&blacklist, "bl", blacklist, "File containing values to insert into the blacklist")
	flag.StringVar(&rulesPath, "r", rulesPath, "Rule file or directory")
	flag.IntVar(&criticalityThresh, "t", criticalityThresh, "Criticality treshold. Prints only if criticality above threshold")

	flag.Usage = func() {
		printInfo(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(exitSuccess)
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
		client := &http.Client{}
		err := utils.HTTPGet(client, geneRulesRepo, databaseZip)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Could not download latest gene-rules: %s", err), exitFail)
		}
		err = utils.Unzip(databaseZip, databasePath)
		if err != nil {
			log.LogErrorAndExit(fmt.Errorf("Could not unzip latest gene-rules: %s", err), exitFail)
		}
		rulesPath = databasePath
	}

	// Control parameters
	if rulesPath == "" {
		log.LogErrorAndExit(fmt.Errorf("No rule file to load"), exitFail)
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
		log.LogErrorAndExit(fmt.Errorf("Cannot resolve %s to file or dir", rulesPath), exitFail)
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

	// Registering handler for interrupt signal
	osSignals := make(chan os.Signal)
	signal.Notify(osSignals, os.Interrupt)
	go func() {
		<-osSignals
		for _ = range []string(listeningChannels) {
			signals <- true
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
			// Try to find an alias to the channel
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
				if n, crit := e.Match(event); len(n) > 0 {
					if crit >= criticalityThresh {
						fmt.Println(string(evtx.ToJSON(event)))
						if winLog {
							winLogger.Log(winLogEventID, "Warning", string(evtx.ToJSON(event)))
						}
						alertsCnt++
					}
				}
				eventCnt++
			}
		}()
	}
	waitGr.Wait()

	stop := time.Now()
	log.Infof("Count Event Scanned: %d", eventCnt)
	log.Infof("Average Event Rate: %.2f EPS", float64(eventCnt)/(stop.Sub(start).Seconds()))
	log.Infof("Alerts Reported: %d", alertsCnt)
	log.Infof("Count Rules Used (loaded + generated): %d", e.Count())
}
