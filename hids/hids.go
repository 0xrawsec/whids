package hids

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/crony"
	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/sod"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/hids/sysinfo"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/sysmon"
	"github.com/0xrawsec/whids/tools"
	"github.com/0xrawsec/whids/utils"
)

const (

	/** Private const **/

	// Container extension
	containerExt = ".cont.gz"
)

var (
	/** Public vars **/

	ContainRuleName = "EDR containment"
	MaxEPS          = float64(300)
	MaxEPSDuration  = 30 * time.Second

	/** Private vars **/

	emptyForwarderConfig = api.ForwarderConfig{}

	// extensions of files to upload to manager
	uploadExts = datastructs.NewInitSyncedSet(".gz", ".sha256")

	archivedRe = regexp.MustCompile(`(CLIP-)??[0-9A-F]{32,}(\..*)?`)

	toolsDir = utils.RelativePath("Tools")
)

// HIDS structure
type HIDS struct {
	sync.RWMutex // Mutex to lock the IDS when updating rules
	ctx          context.Context
	cancel       context.CancelFunc

	// task scheduler
	scheduler *crony.Crony

	eventProvider   *etw.Consumer
	stats           *EventStats
	preHooks        *HookManager
	postHooks       *HookManager
	forwarder       *api.Forwarder
	channels        *datastructs.SyncedSet // Windows log channels to listen to
	channelsSignals chan bool
	config          *Config
	waitGroup       sync.WaitGroup

	flagProcTermEn bool
	bootCompleted  bool
	// Sysmon GUID of HIDS process
	guid          string
	tracker       *ActivityTracker
	actionHandler *ActionHandler
	memdumped     *datastructs.SyncedSet
	dumping       *datastructs.SyncedSet
	filedumped    *datastructs.SyncedSet

	systemInfo *sysinfo.SystemInfo

	// local structure database
	db *sod.DB

	Engine   *engine.Engine
	DryRun   bool
	PrintAll bool
}

func newActionnableEngine(c *Config) (e *engine.Engine) {
	e = engine.NewEngine()
	e.ShowActions = true
	if c.Actions.Low != nil {
		e.SetDefaultActions(actionLowLow, actionLowHigh, c.Actions.Low)
	}
	if c.Actions.Medium != nil {
		e.SetDefaultActions(actionMediumLow, actionMediumHigh, c.Actions.Medium)
	}
	if c.Actions.High != nil {
		e.SetDefaultActions(actionHighLow, actionHighHigh, c.Actions.High)
	}
	if c.Actions.Critical != nil {
		e.SetDefaultActions(actionCriticalLow, actionCriticalHigh, c.Actions.Critical)
	}
	return
}

// NewHIDS creates a new HIDS object from configuration
func NewHIDS(c *Config) (h *HIDS, err error) {

	ctx, cancel := context.WithCancel(context.Background())

	h = &HIDS{
		ctx:             ctx,
		cancel:          cancel,
		scheduler:       crony.NewWithContext(ctx),
		eventProvider:   etw.NewRealTimeConsumer(ctx),
		stats:           NewEventStats(MaxEPS, MaxEPSDuration),
		preHooks:        NewHookMan(),
		postHooks:       NewHookMan(),
		channels:        datastructs.NewSyncedSet(),
		channelsSignals: make(chan bool),
		config:          c,
		waitGroup:       sync.WaitGroup{},
		tracker:         NewActivityTracker(),
		memdumped:       datastructs.NewSyncedSet(),
		dumping:         datastructs.NewSyncedSet(),
		filedumped:      datastructs.NewSyncedSet(),
		// has to be empty to post structure the first time
		systemInfo: &sysinfo.SystemInfo{},
		db:         sod.Open(c.DatabasePath),
	}

	// initializing action manager
	h.actionHandler = NewActionHandler(h)

	// Creates missing directories
	c.Prepare()

	// Create logfile asap if needed
	if c.Logfile != "" {
		log.SetLogfile(c.Logfile, 0600)
	}

	// initialize database
	if err = h.initDB(); err != nil {
		return
	}

	// Verify configuration
	if err = c.Verify(); err != nil {
		return
	}

	// loading forwarder config
	if h.forwarder, err = api.NewForwarder(c.FwdConfig); err != nil {
		return
	}

	// cleaning up previous runs
	h.cleanup()

	// initialization
	h.initEnvVariables()
	h.initEventProvider()
	h.initHooks(c.EnableHooks)
	// initializing canaries
	h.config.CanariesConfig.Configure()
	// fixing local audit policies if necessary
	h.config.AuditConfig.Configure()

	// update and load engine
	if err = h.update(true); err != nil {
		return
	}

	return
}

/** Private Methods **/

func (h *HIDS) initEnvVariables() {
	os.Setenv(los.PathEnvVar, los.BuildPathEnv(los.GetPathEnv(), toolsDir))
}

func (h *HIDS) initDB() (err error) {

	if err = h.db.Create(&tools.Tool{}, sod.DefaultSchema); err != nil {
		return
	}

	return
}

func (h *HIDS) initEventProvider() {

	// parses the providers and init filters
	for _, sprov := range h.config.EtwConfig.UnifiedProviders() {
		if prov, err := etw.ProviderFromString(sprov); err != nil {
			log.Errorf("Error while parsing provider %s: %s", sprov, err)
		} else {
			h.eventProvider.Filter.FromProvider(&prov)
		}
	}

	// open traces
	for _, trace := range h.config.EtwConfig.UnifiedTraces() {
		if err := h.eventProvider.OpenTrace(trace); err != nil {
			log.Errorf("Failed to open trace %s: %s", trace, err)
		}
	}
}

func (h *HIDS) initHooks(advanced bool) {
	// We enable those hooks anyway since it is needed to skip
	// events generated by WHIDS process. These ar very light hooks
	h.preHooks.Hook(hookSelfGUID, fltImageSize)
	h.preHooks.Hook(hookProcTerm, fltProcTermination)
	h.preHooks.Hook(hookStats, fltStats)
	h.preHooks.Hook(hookTrack, fltTrack)
	if advanced {
		// Process terminator hook, terminating blacklisted (by action) processes
		h.preHooks.Hook(hookTerminator, fltProcessCreate)
		h.preHooks.Hook(hookImageLoad, fltImageLoad)
		h.preHooks.Hook(hookSetImageSize, fltImageSize)
		h.preHooks.Hook(hookProcessIntegrityProcTamp, fltImageTampering)
		h.preHooks.Hook(hookEnrichServices, fltAnySysmon)
		h.preHooks.Hook(hookClipboardEvents, fltClipboard)
		h.preHooks.Hook(hookFileSystemAudit, fltFSObjectAccess)
		// Must be run the last as it depends on other filters
		h.preHooks.Hook(hookEnrichAnySysmon, fltAnySysmon)
		h.preHooks.Hook(hookKernelFiles, fltKernelFile)

		// This hook must run before action handling as we want
		// the gene score to be set before an eventual reporting
		h.postHooks.Hook(hookUpdateGeneScore, fltAnyEvent)
	}
}

func (h *HIDS) update(force bool) (last error) {
	var reloadRules, reloadContainers bool

	// check that we are connected to any manager
	if h.config.IsForwardingEnabled() {
		reloadRules = h.needsRulesUpdate()
		reloadContainers = h.needsIoCsUpdate()
	}

	// check if we need rule update
	if reloadRules {
		log.Info("Updating WHIDS rules")
		if err := h.fetchRulesFromManager(); err != nil {
			log.Errorf("Failed to fetch rules from manager: %s", err)
			reloadRules = false
		}
	}

	if reloadContainers {
		log.Info("Updating WHIDS containers")
		if err := h.fetchIoCsFromManager(); err != nil {
			log.Errorf("Failed to fetch containers from manager: %s", err)
			reloadContainers = false
		}
	}

	log.Debugf("reloading rules:%t containers:%t forced:%t", reloadRules, reloadContainers, force)
	if reloadRules || reloadContainers || force {
		// We need to create a new engine if we received a rule/containers update
		newEngine := newActionnableEngine(h.config)

		// containers must be loaded before the rules anyway
		log.Infof("Loading HIDS containers (used in rules) from: %s", h.config.RulesConfig.ContainersDB)
		if err := h.loadContainers(newEngine); err != nil {
			err = fmt.Errorf("failed at loading containers: %s", err)
			last = err
		}

		// Loading IOC container rules
		for _, rule := range IoCRules {
			if err := newEngine.LoadRule(&rule); err != nil {
				log.Errorf("Failed to load IoC rule: %s", err)
				last = err
			}
		}

		// Loading canary rules
		if h.config.CanariesConfig.Enable {
			log.Infof("Loading canary rules")
			// Sysmon rule
			sr := h.config.CanariesConfig.GenRuleSysmon()
			if err := newEngine.LoadRule(&sr); err != nil {
				log.Errorf("Failed to load canary rule: %s", err)
				last = err
			}

			// File System Audit Rule
			fsr := h.config.CanariesConfig.GenRuleFSAudit()
			if err := newEngine.LoadRule(&fsr); err != nil {
				log.Errorf("Failed to load canary rule: %s", err)
				last = err
			}

			// File System Audit Rule
			kfr := h.config.CanariesConfig.GenRuleKernelFile()
			if err := newEngine.LoadRule(&kfr); err != nil {
				log.Errorf("Failed to load canary rule: %s", err)
				last = err
			}
		}

		// Loading rules
		log.Infof("Loading HIDS rules from: %s", h.config.RulesConfig.RulesDB)
		if err := newEngine.LoadDirectory(h.config.RulesConfig.RulesDB); err != nil {
			last = fmt.Errorf("failed to load rules: %s", err)
		}
		log.Infof("Number of rules loaded in engine: %d", newEngine.Count())

		// updating engine if no error
		if last == nil {
			// we update engine only if there was no error
			// no need to lock HIDS as newEngine is ready to use at this point
			h.Engine = newEngine
		} else {
			log.Error("EDR engine not updated:", last)
		}
	} else {
		log.Debug("Neither rules nor containers need to be updated")
	}

	return
}

// rules needs to be updated with the new ones available in manager
func (h *HIDS) needsRulesUpdate() bool {
	var err error
	var oldSha256, sha256 string
	_, rulesSha256Path := h.config.RulesConfig.RulesPaths()

	// Don't need update if not connected to a manager
	if !h.config.IsForwardingEnabled() {
		return false
	}

	if sha256, err = h.forwarder.Client.GetRulesSha256(); err != nil {
		log.Errorf("Failed to fetch rules sha256: %s", err)
		return false
	}

	oldSha256, _ = utils.ReadFileString(rulesSha256Path)

	// log message only if we need to update
	if oldSha256 != sha256 {
		log.Infof("Rules: remote=%s local=%s", sha256, oldSha256)
	}

	return oldSha256 != sha256
}

// returns true if a container needs to be updated
func (h *HIDS) needsIoCsUpdate() bool {
	var localSha256, remoteSha256 string

	// Don't need update if not connected to a manager
	if !h.config.IsForwardingEnabled() {
		return false
	}

	container := api.IoCContainerName
	_, locContSha256Path := h.containerPaths(container)

	// means that remoteCont is also a local container
	remoteSha256, _ = h.forwarder.Client.GetIoCsSha256()
	localSha256, _ = utils.ReadFileString(locContSha256Path)

	// log message only if we need to update
	if localSha256 != remoteSha256 {
		log.Infof("container %s: remote=%s local=%s", container, remoteSha256, localSha256)
	}

	return localSha256 != remoteSha256
}

func (h *HIDS) fetchRulesFromManager() (err error) {
	var rules, sha256 string

	rulePath, sha256Path := h.config.RulesConfig.RulesPaths()

	// if we are not connected to a manager we return
	if h.config.FwdConfig.Local {
		return
	}

	log.Infof("Fetching new rules available in manager")
	if sha256, err = h.forwarder.Client.GetRulesSha256(); err != nil {
		return err
	}

	if rules, err = h.forwarder.Client.GetRules(); err != nil {
		return err
	}

	if sha256 != data.Sha256([]byte(rules)) {
		return fmt.Errorf("failed to verify rules integrity")
	}

	ioutil.WriteFile(sha256Path, []byte(sha256), 0600)
	return ioutil.WriteFile(rulePath, []byte(rules), 0600)
}

// containerPaths returns the path to the container and the path to its sha256 file
func (h *HIDS) containerPaths(container string) (path, sha256Path string) {
	path = filepath.Join(h.config.RulesConfig.ContainersDB, fmt.Sprintf("%s%s", container, containerExt))
	sha256Path = fmt.Sprintf("%s.sha256", path)
	return
}

func (h *HIDS) fetchIoCsFromManager() (err error) {
	var iocs []string
	cl := h.forwarder.Client

	// if we are not connected to a manager we return
	if h.config.FwdConfig.Local {
		return
	}

	if iocs, err = cl.GetIoCs(); err != nil {
		return
	}

	// we compare the integrity of the container received
	compSha256 := utils.Sha256StringArray(iocs)

	if sha256, err := cl.GetIoCsSha256(); err != nil {
		return fmt.Errorf("failed to get IoCs sha256: %s", err)
	} else if compSha256 != sha256 {
		return fmt.Errorf("failed to verify container \"%s\" integrity", api.IoCContainerName)
	}

	// we dump the container
	contPath, contSha256Path := h.containerPaths(api.IoCContainerName)
	fd, err := utils.HidsCreateFile(contPath)
	if err != nil {
		return err
	}
	// closing underlying file
	defer fd.Close()

	w := gzip.NewWriter(fd)
	// closing gzip writer
	defer w.Close()
	for _, ioc := range iocs {
		if _, err = w.Write([]byte(fmt.Sprintln(ioc))); err != nil {
			return
		}
	}

	if err = w.Close(); err != nil {
		return
	}

	if err = fd.Close(); err != nil {
		return
	}

	// Dump current container sha256 to a file
	return ioutil.WriteFile(contSha256Path, []byte(compSha256), 0600)
}

// loads containers found in container database directory
func (h *HIDS) loadContainers(engine *engine.Engine) (lastErr error) {
	for wi := range fswalker.Walk(h.config.RulesConfig.ContainersDB) {
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
				r, err := gzip.NewReader(fd)
				if err != nil {
					lastErr = err
					// we close file descriptor
					fd.Close()
					continue
				}
				log.Infof("Loading container %s from path %s", cont, path)
				if err = engine.LoadContainer(cont, r); err != nil {
					lastErr = fmt.Errorf("failed to load container %s: %s", cont, err)
					log.Error(lastErr)
				}
				r.Close()
				fd.Close()
			}
		}
	}
	return
}

func (h *HIDS) updateSystemInfo() (err error) {
	var hnew, hold string

	new := sysinfo.NewSystemInfo()
	if hnew, err = utils.HashStruct(new); err != nil {
		// we return cause we don't want to overwrite with
		// a faulty structure
		return
	}

	// if it returns an error we don't really care because
	// it will be replaced by new
	hold, _ = utils.HashStruct(h.systemInfo)

	if hnew != hold {
		h.systemInfo = new
		return h.forwarder.Client.PostSystemInfo(h.systemInfo)
	}

	return
}

/*
Warning: we cannot use binary hash information to decide wether we
need to update because Sysmon.exe (32 bit version) contains both the
32 and 64 bit version of the tool. When Sysmon gets installed only one
of the two versions is installed.
*/
func (h *HIDS) updateSysmon() (err error) {
	var version string

	si := sysmon.NewSysmonInfo()
	sysmonPath := filepath.Join(toolsDir, tools.WithExecExt(tools.ToolSysmon))

	if !fsutil.IsFile(sysmonPath) {
		// no Sysmon tool so nothing to do
		return
	}

	if version, _, _, err = sysmon.Versions(sysmonPath); err != nil {
		return fmt.Errorf("failed to retrieve tool's version: %w", err)
	}

	if si.Version == version {
		// Sysmon in tools' directory is same version as
		// the one installed -> nothing to do
		return
	}

	// we install or update Sysmon
	log.Infof("Install/updating sysmon old=%s new=%s", si.Version, version)
	if err = sysmon.InstallOrUpdate(sysmonPath); err != nil {
		return fmt.Errorf("failed to install/update sysmon: %w", err)
	}

	// updating system information before config update as config update
	// may return on error
	if err = h.updateSystemInfo(); err != nil {
		return fmt.Errorf("failed to update system info: %w", err)
	}

	log.Info("Updating sysmon config")
	// we update configuration
	if err = h.updateSysmonConfig(); err != nil {
		return fmt.Errorf("failed to update sysmon config: %w", err)
	}

	return
}

func (h *HIDS) updateSysmonConfig() (err error) {
	var remoteSha256 string
	var xml []byte
	var cfg *sysmon.Config

	c := h.forwarder.Client
	systemInfo := sysinfo.NewSystemInfo()
	schemaVersion := systemInfo.Sysmon.Config.Version.Schema
	sha256 := systemInfo.Sysmon.Config.Hash

	remoteSha256, err = c.GetSysmonConfigSha256(schemaVersion)

	switch err {
	case nil:
		// if we go here it means there is a configuration available in manager
		// Nothing to do
		if remoteSha256 == sha256 {
			return
		}

		// getting sysmon configuration from manager
		if cfg, err = c.GetSysmonConfig(schemaVersion); err != nil {
			return
		}

	case api.ErrNoSysmonConfig:
		// no configuration available on the manager

		log.Info("No Sysmon config found on manager, trying to use default config")

		if cfg, err = sysmon.AgnosticConfig(schemaVersion); err != nil {
			return
		}

	default:
		return
	}

	if sha256 == cfg.XmlSha256 {
		// we can skip sysmon configuration update as the current configuration
		// is the same as the one we want to apply
		return
	}

	log.Infof("Deploying new sysmon configuration old=%s new=%s", sha256, cfg.XmlSha256)
	if xml, err = cfg.XML(); err != nil {
		return
	}

	if err = sysmon.Configure(bytes.NewBuffer(xml)); err != nil {
		return fmt.Errorf("failed to configure sysmon: %w", err)
	}

	if err = h.updateSystemInfo(); err != nil {
		err = fmt.Errorf("failed to update system info: %w", err)
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

/** Public Methods **/

// IsHIDSEvent returns true if the event is generated by IDS activity
func (h *HIDS) IsHIDSEvent(e *event.EdrEvent) bool {
	if pguid, ok := e.GetString(pathSysmonParentProcessGUID); ok {
		if pguid == h.guid {
			return true
		}
	}

	if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
		if guid == h.guid {
			return true
		}
		// search for parent in processTracker
		if pt := h.tracker.GetByGuid(guid); !pt.IsZero() {
			if pt.ParentProcessGUID == h.guid {
				return true
			}
		}
	}
	if sguid, ok := e.GetString(pathSysmonSourceProcessGUID); ok {
		if sguid == h.guid {
			return true
		}
		// search for parent in processTracker
		if pt := h.tracker.GetByGuid(sguid); !pt.IsZero() {
			if pt.ParentProcessGUID == h.guid {
				return true
			}
		}
	}
	return false
}

// Report generate a forensic ready report (meant to be dumped)
// this method is blocking as it runs commands and wait after those
func (h *HIDS) Report(light bool) (r Report) {
	r.StartTime = time.Now()

	// generate a report for running processes or those terminated still having one child or more
	// do this step first not to polute report with commands to run
	r.Processes = h.tracker.PS()

	// Modules ever loaded
	r.Modules = h.tracker.Modules()

	// Drivers loaded
	r.Drivers = h.tracker.Drivers

	// if this is a light report, we don't run the commands
	if !light {
		// run all the commands configured to include in the report
		r.Commands = h.config.Report.PrepareCommands()
		for i := range r.Commands {
			r.Commands[i].Run()
		}
	}

	r.StopTime = time.Now()
	return
}

// Run starts the WHIDS engine and waits channel listening is stopped
func (h *HIDS) Run() {
	// Running all the threads
	// Runs the forwarder
	h.forwarder.Run()

	// Running action manager
	h.actionHandler.Run()

	// Start the update routine
	//log.Infof("Update routine running: %t", h.updateRoutine())
	// starting dump forwarding routine
	//log.Infof("Dump forwarding routine running: %t", h.uploadRoutine())
	// running the command runner routine
	//log.Infof("Command runner routine running: %t", h.commandRunnerRoutine())
	// start the archive cleanup routine (might create a new thread)
	//log.Infof("Sysmon archived files cleanup routine running: %t", h.scheduleCleanArchivedTask())
	h.scheduleTasks()
	for _, t := range h.scheduler.Tasks() {
		log.Infof("Scheduler running: %s", t.Name)
	}

	// Dry run don't do anything
	if h.DryRun {
		for _, trace := range h.config.EtwConfig.UnifiedTraces() {
			log.Infof("Dry run: would open trace %s", trace)
		}
		return
	}

	// Starting event provider
	h.eventProvider.Start()

	// start stats monitoring
	h.stats.Start()

	h.waitGroup.Add(1)
	go func() {
		defer h.waitGroup.Done()

		// Trying to raise thread priority
		if err := kernel32.SetCurrentThreadPriority(win32.THREAD_PRIORITY_ABOVE_NORMAL); err != nil {
			log.Errorf("Failed to raise IDS thread priority: %s", err)
		}

		for e := range h.eventProvider.Events {
			event := event.NewEdrEvent(e)

			if yes, eps := h.stats.HasPerfIssue(); yes {
				log.Warnf("Average event rate above limit of %.2f e/s in the last %s: %.2f e/s", h.stats.Threshold(), h.stats.Duration(), eps)

				if h.stats.HasCriticalPerfIssue() {
					log.Critical("Event throughput too high for too long, consider filtering out events")
				} else if crit := h.stats.CriticalEPS(); eps > crit {
					log.Criticalf("Event throughput above %.0fx the limit, if repeated consider filtering out events", eps/h.stats.Threshold())
				}
			}

			// Warning message in certain circumstances
			if h.config.EnableHooks && !h.flagProcTermEn && h.stats.Events() > 0 && int64(h.stats.Events())%1000 == 0 {
				log.Warn("Sysmon process termination events seem to be missing. WHIDS won't work as expected.")
			}

			h.RLock()

			// Runs pre detection hooks
			// putting this before next condition makes the processTracker registering
			// HIDS events and allows detecting ProcessAccess events from HIDS childs
			h.preHooks.RunHooksOn(h, event)

			// We skip if it is one of IDS event
			// we keep process termination event because it is used to control if process termination is enabled
			if h.IsHIDSEvent(event) && !isSysmonProcessTerminate(event) {
				if h.PrintAll {
					fmt.Println(utils.JsonString(event))
				}
				goto Continue
			}

			// if event is skipped we don't log it even with PrintAll
			if event.IsSkipped() {
				h.stats.Update(event)
				goto Continue
			}

			// if the event has matched at least one signature or is filtered
			if n, crit, filtered := h.Engine.MatchOrFilter(event); len(n) > 0 || filtered {
				switch {
				case crit >= h.config.CritTresh:
					if !h.PrintAll && !h.config.LogAll {
						h.forwarder.PipeEvent(event)
					}
					// Pipe the event to be sent to the forwarder
					// Run hooks post detection
					h.postHooks.RunHooksOn(h, event)
					h.stats.Update(event)
				case filtered && h.config.EnableFiltering && !h.PrintAll && !h.config.LogAll:
					//event.Del(&engine.GeneInfoPath)
					// we pipe filtered event
					h.forwarder.PipeEvent(event)
				}
			}

			// we queue event in action manager
			h.actionHandler.Queue(event)

			// Print everything
			if h.PrintAll {
				fmt.Println(utils.JsonString(event))
			}

			// We log all events
			if h.config.LogAll {
				h.forwarder.PipeEvent(event)
			}

			h.stats.Update(event)

		Continue:
			h.RUnlock()
		}
		log.Infof("HIDS main loop terminated")
	}()

	// Run bogus command so that at least one Process Terminate
	// is generated (used to check if process termination events are enabled)
	exec.Command(os.Args[0], "-h").Start()
}

// LogStats logs whids statistics
func (h *HIDS) LogStats() {
	log.Infof("Time Running: %s", h.stats.SinceStart())
	log.Infof("Count Event Scanned: %.0f", h.stats.Events())
	log.Infof("Average Event Rate: %.2f EPS", h.stats.EPS())
	log.Infof("Alerts Reported: %.0f", h.stats.Detections())
	log.Infof("Count Rules Used (loaded + generated): %d", h.Engine.Count())
}

// Stop stops the IDS
func (h *HIDS) Stop() {
	log.Infof("Stopping HIDS")
	// cancelling parent context
	h.cancel()
	// gently close forwarder needs to be done before
	// stop listening othewise we corrupt local logfiles
	// because of race condition
	log.Infof("Closing forwarder")
	h.forwarder.Close()

	// closing event provider
	log.Infof("Closing event provider")
	if err := h.eventProvider.Stop(); err != nil {
		log.Errorf("Error while closing event provider: %s", err)
	}

	// cleaning canary files
	if h.config.CanariesConfig.Enable {
		log.Infof("Cleaning canaries")
		h.config.CanariesConfig.Clean()
	}

	// updating autologger configuration
	log.Infof("Updating autologger configuration")
	if err := Autologger.Delete(); err != nil {
		log.Errorf("Failed to delete autologger:", err)
	}

	if err := h.config.EtwConfig.ConfigureAutologger(); err != nil {
		log.Errorf("Failed to update autologger configuration:", err)
	}

	log.Infof("HIDS stopped")
}

// Wait waits the IDS to finish
func (h *HIDS) Wait() {
	h.waitGroup.Wait()
}

// WaitWithTimeout waits the IDS to finish
func (h *HIDS) WaitWithTimeout(timeout time.Duration) {
	t := time.NewTimer(timeout)
	go func() {
		h.waitGroup.Wait()
		t.Stop()
	}()
	<-t.C
}
