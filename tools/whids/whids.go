package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
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
	// Default permissions for output files
	defaultPerms = 0640

	// Container extension
	containerExt = ".cont.gz"
)

var (
	abs, _ = filepath.Abs(filepath.Dir(os.Args[0]))

	dumpOptions = []string{"memory", "file", "all"}

	channelAliases = map[string]string{
		"sysmon":   "Microsoft-Windows-Sysmon/Operational",
		"security": "Security",
		"ps":       "Microsoft-Windows-PowerShell/Operational",
		"defender": "Microsoft-Windows-Windows Defender/Operational",
		"all":      "All aliased channels",
	}

	// extensions of files to upload to manager
	uploadExts = datastructs.NewInitSyncedSet(".gz", ".sha256")
)

func allChannels() []string {
	channels := make([]string, 0, len(channelAliases))
	for alias, channel := range channelAliases {
		if alias != "all" {
			channels = append(channels, channel)
		}
	}
	return channels
}

var (
	emptyForwarderConfig = collector.ForwarderConfig{}
	logDir               = filepath.Join(abs, "Logs")

	// DefaultHIDSConfig is the default HIDS configuration
	DefaultHIDSConfig = HIDSConfig{
		RulesDB:      filepath.Join(abs, "Database", "Rules"),
		ContainersDB: filepath.Join(abs, "Database", "Containers"),
		FwdConfig: collector.ForwarderConfig{
			Local: true,
			Client: collector.ClientConfig{
				MaxUploadSize: collector.DefaultMaxUploadSize,
			},
			Logging: collector.LoggingConfig{
				Dir:              filepath.Join(logDir, "Alerts"),
				RotationInterval: "24h",
			},
		},
		Channels: []string{"all"},
		Dump: DumpConfig{
			Mode:        "file|registry",
			Treshold:    8,
			Dir:         filepath.Join(abs, "Dumps"),
			Compression: true,
		},
		CritTresh:      5,
		UpdateInterval: 60,
		Logfile:        filepath.Join(logDir, "whids.log"),
		EnableHooks:    true,
		Endpoint:       true,
		LogAll:         false}
)

// DumpConfig structure definition
type DumpConfig struct {
	Mode        string `json:"mode"`
	Treshold    int    `json:"treshold"`
	Dir         string `json:"dir"`
	Compression bool   `json:"compression"`
}

// IsModeEnabled checks if dump mode is enabled
func (d *DumpConfig) IsModeEnabled(mode string) bool {
	if strings.Index(d.Mode, "all") != -1 {
		return true
	}
	return strings.Index(d.Mode, mode) != -1
}

// HIDSConfig structure
type HIDSConfig struct {
	RulesDB        string                    `json:"rules-db"`
	ContainersDB   string                    `json:"containers-db"`
	FwdConfig      collector.ForwarderConfig `json:"forwarder"`
	Channels       []string                  `json:"channels"`
	Dump           DumpConfig                `json:"dump"`
	CritTresh      int                       `json:"criticality-treshold"`
	UpdateInterval time.Duration             `json:"update-interval"`
	EnableHooks    bool                      `json:"en-hooks"`
	Logfile        string                    `json:"logfile"` // for WHIDS log messages (not alerts)
	LogAll         bool                      `json:"log-all"` // log all events to logfile (used for debugging)
	Endpoint       bool                      `json:"endpoint"`
}

// LoadsHIDSConfig loads a HIDS configuration from a file
func LoadsHIDSConfig(path string) (c HIDSConfig, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return
	}
	defer fd.Close()
	dec := json.NewDecoder(fd)
	err = dec.Decode(&c)
	return
}

// SetHooksGlobals sets the global variables used by hooks
func (c *HIDSConfig) SetHooksGlobals() {
	dumpDirectory = c.Dump.Dir
	dumpTresh = c.Dump.Treshold
	flagDumpCompress = c.Dump.Compression
}

// IsDumpEnabled returns true if any kind of dump is enabled
func (c *HIDSConfig) IsDumpEnabled() bool {
	// Dump can be enabled only in endpoint mode
	return c.Endpoint && (c.Dump.IsModeEnabled("file") || c.Dump.IsModeEnabled("registry") || c.Dump.IsModeEnabled("memory"))
}

// IsForwardingEnabled returns true if a forwarder is actually configured to forward logs
func (c *HIDSConfig) IsForwardingEnabled() bool {
	return c.FwdConfig != emptyForwarderConfig && !c.FwdConfig.Local
}

// Prepare creates directory used in the config if not existing
func (c *HIDSConfig) Prepare() {
	if !fsutil.Exists(c.RulesDB) {
		os.MkdirAll(c.RulesDB, 0600)
	}
	if !fsutil.Exists(c.ContainersDB) {
		os.MkdirAll(c.ContainersDB, 0600)
	}
	if !fsutil.Exists(c.Dump.Dir) {
		os.MkdirAll(c.Dump.Dir, 0600)
	}
	if !fsutil.Exists(filepath.Dir(c.FwdConfig.Logging.Dir)) {
		os.MkdirAll(filepath.Dir(c.FwdConfig.Logging.Dir), 0600)
	}
	if !fsutil.Exists(filepath.Dir(c.Logfile)) {
		os.MkdirAll(filepath.Dir(c.Logfile), 0600)
	}
}

// Verify validate HIDS configuration object
func (c *HIDSConfig) Verify() error {
	if !fsutil.IsDir(c.RulesDB) {
		return fmt.Errorf("Rules database must be a directory")
	}
	if !fsutil.IsDir(c.ContainersDB) {
		return fmt.Errorf("Containers database must be a directory")
	}
	return nil
}

// HIDS structure
type HIDS struct {
	sync.RWMutex    // Mutex to lock the IDS when updating rules
	eventProvider   wevtapi.EventProvider
	engine          engine.Engine
	preHooks        *hooks.HookManager
	postHooks       *hooks.HookManager
	forwarder       *collector.Forwarder
	channels        datastructs.SyncedSet // Windows log channels to listen to
	channelsSignals chan bool
	config          *HIDSConfig
	eventScanned    uint64
	alertReported   uint64
	startTime       time.Time
	waitGroup       sync.WaitGroup

	DryRun   bool
	PrintAll bool
}

// NewHIDS creates a new HIDS object from configuration
func NewHIDS(c *HIDSConfig) (h *HIDS, err error) {
	h = &HIDS{
		// PushEventProvider seems not to retrieve all the events (observed this at boot)
		eventProvider:   wevtapi.NewPullEventProvider(),
		preHooks:        hooks.NewHookMan(),
		postHooks:       hooks.NewHookMan(),
		channels:        datastructs.NewSyncedSet(),
		channelsSignals: make(chan bool),
		config:          c,
		waitGroup:       sync.WaitGroup{}}

	// Creates missing directories
	c.Prepare()

	// Create logfile asap if needed
	if c.Logfile != "" {
		log.SetLogfile(c.Logfile, 600)
	}

	// Set the globals used by the Hooks
	c.SetHooksGlobals()

	// Verify configuration
	if err = c.Verify(); err != nil {
		return nil, err
	}

	// loading forwarder config
	if h.forwarder, err = collector.NewForwarder(&c.FwdConfig); err != nil {
		return nil, err
	}

	// cleaning up previous runs
	h.cleanup()

	// initialization
	h.initChannels(c.Channels)
	h.initHooks(c.EnableHooks)
	// tries to update the engine
	if err := h.updateEngine(true); err != nil {
		return h, err
	}
	return h, nil
}

func (h *HIDS) initChannels(channels []string) {
	for _, c := range channels {
		if c == "all" {
			h.channels.Add(datastructs.ToInterfaceSlice(allChannels())...)
			continue
		}
		if rc, ok := channelAliases[c]; ok {
			h.channels.Add(rc)
		} else {
			h.channels.Add(c)
		}
	}
}

func (h *HIDS) initHooks(advanced bool) {
	// We enable those hooks anyway since it is needed to skip
	// events generated by WHIDS process. These ar very light hooks
	h.preHooks.Hook(hookSelfGUID, fltImageSize)
	h.preHooks.Hook(hookProcTerm, fltProcTermination)
	h.preHooks.Hook(hookStats, fltStats)
	h.preHooks.Hook(hookTrack, fltProcessCreate)
	if advanced {
		h.preHooks.Hook(hookImageLoad, fltImageLoad)
		h.preHooks.Hook(hookSetImageSize, fltImageSize)
		h.preHooks.Hook(hookProcessIntegrity, fltImageSize)
		h.preHooks.Hook(hookEnrichServices, fltAnySysmon)
		// Not needed anymore enrich sysmon embeds necessary information
		//h.preHooks.Hook(hookProcessAccess, fltProcessAccess)
		// should be treated by hookEnrichAnySysmon
		//h.preHooks.Hook(hookNetwork, fltNetworkConnect)
		h.preHooks.Hook(hookEnrichAnySysmon, fltAnySysmon)
		//h.preHooks.Hook(hookSetValueSize, fltRegSetValue)

		// Registering post detection hooks
		// if endpoint we enable dump features
		if h.config.Endpoint {
			if h.config.Dump.IsModeEnabled("registry") {
				h.postHooks.Hook(hookDumpRegistry, fltRegSetValue)
			}
			if h.config.Dump.IsModeEnabled("file") {
				h.postHooks.Hook(hookDumpFile, fltAnySysmon)
			}
			if h.config.Dump.IsModeEnabled("memory") {
				h.postHooks.Hook(hookDumpProcess, fltAnySysmon)
			}
		}
	}
}

// returns true if the update routine is started
func (h *HIDS) updateRoutine() bool {
	d := h.config.UpdateInterval * time.Second
	if h.config.IsForwardingEnabled() {
		if d > 0 {
			go func() {
				t := time.NewTimer(d)
				for range t.C {
					if err := h.updateEngine(false); err != nil {
						log.Error(err)
					}
					t.Reset(d)
				}
			}()
			return true
		}
	}
	return false
}

func (h *HIDS) updateEngine(force bool) error {
	h.Lock()
	defer h.Unlock()

	var reloadRules, reloadContainers bool

	// check if we need rule update
	if h.needsRulesUpdate() {
		log.Info("Updating WHIDS rules")
		if err := h.updateRules(); err != nil {
			log.Errorf("Failed to update rules: %s", err)
		} else {
			reloadRules = true
		}
	}

	if h.needsContainersUpdate() {
		log.Info("Updating WHIDS containers")
		if err := h.updateContainers(); err != nil {
			log.Errorf("Failed to update containers: %s", err)
		} else {
			reloadContainers = true
		}
	}

	if reloadRules || reloadContainers || force {
		// We need to create a new engine if we received a rule/containers update
		h.engine = engine.NewEngine(false)

		// containers must be loaded before the rules anyway
		log.Infof("Loading HIDS containers (used in rules) from: %s", h.config.ContainersDB)
		if err := h.loadContainers(); err != nil {
			return fmt.Errorf("Error loading containers: %s", err)
		}

		if reloadRules || force {
			log.Infof("Loading HIDS rules from: %s", h.config.RulesDB)
			if err := h.engine.LoadDirectory(h.config.RulesDB); err != nil {
				return fmt.Errorf("Failed to load rules: %s", err)
			}
			log.Infof("Number of rules loaded in engine: %d", h.engine.Count())
		}
	} else {
		log.Info("Neither rules nor containers need to be updated")
	}

	return nil
}

// rules needs to be updated with the new ones available in manager
func (h *HIDS) needsRulesUpdate() bool {
	var err error
	var oldSha256, sha256 string
	_, rulesSha256Path := h.rulesPaths()

	if h.forwarder.Local {
		return false
	}

	if sha256, err = h.forwarder.Client.GetRulesSha256(); err != nil {
		return false
	}
	oldSha256, _ = utils.ReadFileString(rulesSha256Path)

	log.Infof("Rules: remote=%s local=%s", sha256, oldSha256)
	if oldSha256 != sha256 {
		return true
	}
	return false
}

// at least one container needs to be updated
func (h *HIDS) needsContainersUpdate() bool {
	var containers []string
	var err error

	cl := h.forwarder.Client

	if h.forwarder.Local {
		return false
	}

	if containers, err = cl.GetContainersList(); err != nil {
		return false
	}

	for _, cont := range containers {
		if h.needsContainerUpdate(cont) {
			return true
		}
	}
	return false
}

// returns true if a container needs to be updated
func (h *HIDS) needsContainerUpdate(remoteCont string) bool {
	var localSha256, remoteSha256 string
	_, locContSha256Path := h.containerPaths(remoteCont)
	// means that remoteCont is also a local container
	remoteSha256, _ = h.forwarder.Client.GetContainerSha256(remoteCont)
	localSha256, _ = utils.ReadFileString(locContSha256Path)
	log.Infof("container %s: remote=%s local=%s", remoteCont, remoteSha256, localSha256)
	if localSha256 != remoteSha256 {
		return true
	}
	return false
}

func (h *HIDS) updateRules() (err error) {
	var rules, sha256 string

	rulePath, sha256Path := h.rulesPaths()

	log.Infof("Loading rules available in manager")
	if sha256, err = h.forwarder.Client.GetRulesSha256(); err != nil {
		return err
	}

	if rules, err = h.forwarder.Client.GetRules(); err != nil {
		return err
	}

	if sha256 != data.Sha256([]byte(rules)) {
		return fmt.Errorf("Failed to verify rules integrity")
	}

	ioutil.WriteFile(sha256Path, []byte(sha256), 600)
	return ioutil.WriteFile(rulePath, []byte(rules), 600)
}

// containerPaths returns the path to the container and the path to its sha256 file
func (h *HIDS) containerPaths(container string) (path, sha256Path string) {
	path = filepath.Join(h.config.ContainersDB, fmt.Sprintf("%s%s", container, containerExt))
	sha256Path = fmt.Sprintf("%s.sha256", path)
	return
}

// rulesPaths returns the path used by WHIDS to save gene rules
func (h *HIDS) rulesPaths() (path, sha256Path string) {
	path = filepath.Join(h.config.RulesDB, "database.gen")
	sha256Path = fmt.Sprintf("%s.sha256", path)
	return
}

func (h *HIDS) updateContainers() (err error) {
	var containers []string
	cl := h.forwarder.Client

	if containers, err = cl.GetContainersList(); err != nil {
		return nil
	}

	for _, contName := range containers {
		// if container needs to be updated
		if h.needsContainerUpdate(contName) {
			cont, err := cl.GetContainer(contName)
			if err != nil {
				return err
			}

			// we compare the integrity of the container received
			compSha256 := collector.Sha256StringArray(cont)
			sha256, _ := cl.GetContainerSha256(contName)
			if compSha256 != sha256 {
				return fmt.Errorf("Failed to verify container \"%s\" integrity", contName)
			}

			// we dump the container
			contPath, contSha256Path := h.containerPaths(contName)
			fd, err := os.Create(contPath)
			if err != nil {
				return err
			}
			w := gzip.NewWriter(fd)
			for _, e := range cont {
				w.Write([]byte(fmt.Sprintln(e)))
			}
			w.Flush()
			w.Close()
			fd.Close()
			// Dump current container sha256 to a file
			ioutil.WriteFile(contSha256Path, []byte(compSha256), 600)
		}
	}
	return nil
}

// loads containers found in container database directory
func (h *HIDS) loadContainers() (lastErr error) {
	for wi := range fswalker.Walk(h.config.ContainersDB) {
		for _, fi := range wi.Files {
			path := filepath.Join(wi.Dirpath, fi.Name())
			// we take only files with good extension
			if strings.HasSuffix(fi.Name(), containerExt) {
				cont := strings.SplitN(fi.Name(), ".", 2)[0]
				fd, err := os.Open(path)
				if err != nil {
					lastErr = err
					continue
				}
				defer fd.Close()
				r, err := gzip.NewReader(fd)
				if err != nil {
					lastErr = err
					continue
				}
				log.Infof("Loading container: %s", cont)
				h.engine.LoadContainer(cont, r)
				r.Close()
				fd.Close()
			}
		}
	}
	return
}

func (h *HIDS) cleanup() {
	// Cleaning up empty dump directories if needed
	fis, _ := ioutil.ReadDir(h.config.Dump.Dir)
	for _, fi := range fis {
		if fi.IsDir() {
			fp := filepath.Join(h.config.Dump.Dir, fi.Name())
			if utils.CountFiles(fp) == 0 {
				os.RemoveAll(fp)
			}
		}
	}
}

func (h *HIDS) uploadRoutine() bool {
	// force compression in this case
	if h.config.IsDumpEnabled() && h.config.IsForwardingEnabled() {
		flagDumpCompress = true
		go func() {
			for {
				// Sending dump files over to the manager
				for wi := range fswalker.Walk(h.config.Dump.Dir) {
					for _, fi := range wi.Files {
						sp := strings.Split(wi.Dirpath, string(os.PathSeparator))
						// upload only file with some extensions
						if uploadExts.Contains(filepath.Ext(fi.Name())) {
							if len(sp) >= 2 {
								fullpath := filepath.Join(wi.Dirpath, fi.Name())
								fu, err := h.forwarder.Client.PrepareFileUpload(fullpath, sp[len(sp)-2], sp[len(sp)-1], fi.Name())
								if err != nil {
									log.Errorf("Failed to prepare dump file to upload: %s", err)
									continue
								}
								if err := h.forwarder.Client.PostDump(fu); err != nil {
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
		return true
	}
	return false
}

// Run starts the WHIDS engine and waits channel listening is stopped
func (h *HIDS) Run() {
	// Runs the forwarder in a separate thread
	h.forwarder.Run()

	// Start the update routine
	log.Infof("Update routine running: %t", h.updateRoutine())
	log.Infof("Dump forwarding routine running: %t", h.uploadRoutine())

	channels := make([]string, 0)
	// We prepare the list of channels
	for it := range h.channels.Items() {
		channel := it.(string)
		channels = append(channels, channel)
	}

	// Dry run don't do anything
	if h.DryRun {
		for _, channel := range channels {
			log.Infof("Dry run: would listen on %s", channel)
		}
		return
	}

	h.startTime = time.Now()
	h.waitGroup.Add(1)
	go func() {
		defer h.waitGroup.Done()
		xmlEvents := h.eventProvider.FetchEvents(channels, wevtapi.EvtSubscribeToFutureEvents)
		for xe := range xmlEvents {
			event, err := XMLEventToGoEvtxMap(xe)
			if err != nil {
				log.Errorf("Failed to convert event: %s", err)
				log.Debugf("Error data: %v", xe)
			}

			// Warning message in certain circumstances
			if h.config.EnableHooks && !flagProcTermEn && h.eventScanned%1000 == 0 {
				log.Warn("Sysmon process termination events seem to be missing. WHIDS won't work as expected.")
			}

			// Runs pre detection hooks
			h.preHooks.RunHooksOn(event)

			// We skip if it is one of our Event
			if isSelf(event) {
				if h.PrintAll {
					fmt.Println(utils.JSON(event))
				}
				continue
			}

			h.RLock()
			if n, crit := h.engine.Match(event); len(n) > 0 {
				if crit >= h.config.CritTresh {
					if !h.PrintAll && !h.config.LogAll {
						h.forwarder.PipeEvent(event)
					}
					// Pipe the event to be sent to the forwarder
					// Run hooks post detection
					h.postHooks.RunHooksOn(event)
					h.alertReported++
				}
			}
			// Print everything
			if h.PrintAll {
				fmt.Println(utils.JSON(event))
			}

			// We log all events
			if h.config.LogAll {
				h.forwarder.PipeEvent(event)
			}

			h.RUnlock()
			h.eventScanned++
		}
	}()

	// Run bogus command so that at least one Process Terminate
	// is generated (used to check if process termination events are enabled)
	exec.Command(os.Args[0], "-h").Start()
}

// LogStats logs whids statistics
func (h *HIDS) LogStats() {
	stop := time.Now()
	log.Infof("Time Running: %s", stop.Sub(h.startTime))
	log.Infof("Count Event Scanned: %d", h.eventScanned)
	log.Infof("Average Event Rate: %.2f EPS", float64(h.eventScanned)/(stop.Sub(h.startTime).Seconds()))
	log.Infof("Alerts Reported: %d", h.alertReported)
	log.Infof("Count Rules Used (loaded + generated): %d", h.engine.Count())
}

// Stop stops the IDS
func (h *HIDS) Stop() {
	log.Infof("Stopping HIDS")
	// gently close forwarder needs to be done before
	// stop listening othewise we corrupt local logfiles
	// because of race condition
	log.Infof("Closing forwarder")
	h.forwarder.Close()
	log.Infof("Closing event provider")
	h.eventProvider.Stop()
	log.Infof("HIDS stopped")
}

// Wait waits the IDS to finish
func (h *HIDS) Wait() {
	h.waitGroup.Wait()
}
