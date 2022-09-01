package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
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
	"github.com/0xrawsec/golog"
	"github.com/0xrawsec/sod"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/agent/sysinfo"
	"github.com/0xrawsec/whids/api/client"
	"github.com/0xrawsec/whids/api/server"
	"github.com/0xrawsec/whids/event"
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

	// extensions of files to upload to manager
	uploadExts = datastructs.NewInitSyncedSet(".gz", ".sha256")

	archivedRe = regexp.MustCompile(`(CLIP-)??[0-9A-F]{32,}(\..*)?`)

	toolsDir = utils.RelativePath("Tools")
)

// Agent structure
type Agent struct {
	sync.RWMutex // Mutex to lock the IDS when updating rules
	ctx          context.Context
	cancel       context.CancelFunc

	// task scheduler
	scheduler *crony.Crony

	eventProvider   *etw.Consumer
	stats           *EventStats
	preHooks        *HookManager
	postHooks       *HookManager
	forwarder       *client.Forwarder
	channels        *datastructs.SyncedSet // Windows log channels to listen to
	channelsSignals chan bool
	config          *config.Agent
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

	//logger
	logger *golog.Logger

	Engine   *engine.Engine
	DryRun   bool
	PrintAll bool
}

func newActionnableEngine(c *config.Agent) (e *engine.Engine) {
	e = engine.NewEngine()
	e.ShowActions = true
	if c.Actions.Low != nil {
		e.SetDefaultActions(config.ActionLowLow, config.ActionLowHigh, c.Actions.Low)
	}
	if c.Actions.Medium != nil {
		e.SetDefaultActions(config.ActionMediumLow, config.ActionMediumHigh, c.Actions.Medium)
	}
	if c.Actions.High != nil {
		e.SetDefaultActions(config.ActionHighLow, config.ActionHighHigh, c.Actions.High)
	}
	if c.Actions.Critical != nil {
		e.SetDefaultActions(config.ActionCriticalLow, config.ActionCriticalHigh, c.Actions.Critical)
	}
	return
}

// NewAgent creates a new Agent object from configuration
func NewAgent(c *config.Agent) (a *Agent, err error) {

	a = &Agent{}
	a.Initialize()

	err = a.Prepare(c)

	return
}

func (a *Agent) Initialize() {
	// context inititialization
	ctx, cancel := context.WithCancel(context.Background())

	a.ctx = ctx
	a.cancel = cancel
	a.scheduler = crony.NewWithContext(ctx)
	a.eventProvider = etw.NewRealTimeConsumer(ctx)
	a.stats = NewEventStats(MaxEPS, MaxEPSDuration)
	a.preHooks = NewHookMan()
	a.postHooks = NewHookMan()
	a.channels = datastructs.NewSyncedSet()
	a.channelsSignals = make(chan bool)
	a.waitGroup = sync.WaitGroup{}
	a.tracker = NewActivityTracker()
	a.memdumped = datastructs.NewSyncedSet()
	a.dumping = datastructs.NewSyncedSet()
	a.filedumped = datastructs.NewSyncedSet()
	// has to be empty to post structure the first time
	a.systemInfo = &sysinfo.SystemInfo{}
	a.logger = golog.FromStdout()
}

func (a *Agent) Prepare(c *config.Agent) (err error) {
	// assigning configuration to agent
	a.config = c

	// opening database
	a.db = sod.Open(c.DatabasePath)

	// initializing action manager
	a.actionHandler = NewActionHandler(a)

	// Creates missing directories
	c.Prepare()

	// Create logfile asap if needed
	if c.Logfile != "" {
		if a.logger, err = golog.FromPath(c.Logfile, 0600); err != nil {
			return
		}
	}

	// initialize database
	if err = a.initDB(); err != nil {
		return
	}

	// Verify configuration
	if err = c.Verify(); err != nil {
		return
	}

	// loading forwarder config
	if a.forwarder, err = client.NewForwarder(a.ctx, &a.config.FwdConfig, a.logger); err != nil {
		return
	}

	// cleaning up previous runs
	a.cleanup()

	// initialization
	a.initEnvVariables()
	a.initEventProvider()
	a.initHooks(c.EnableHooks)
	// schedule tasks
	a.scheduleTasks()
	// fixing local audit policies if necessary
	a.configureAuditPolicies()

	// update and load engine
	if err = a.update(true); err != nil {
		return
	}

	return
}

/** Private Methods **/

func (a *Agent) initEnvVariables() {
	os.Setenv(los.PathEnvVar, los.BuildPathEnv(los.GetPathEnv(), toolsDir))
}

func (a *Agent) initDB() (err error) {

	if err = a.db.Create(&tools.Tool{}, sod.DefaultSchema); err != nil {
		return
	}

	return
}

func (a *Agent) initEventProvider() {

	// parses the providers and init filters
	for _, sprov := range a.config.EtwConfig.UnifiedProviders() {
		if prov, err := etw.ParseProvider(sprov); err != nil {
			a.logger.Errorf("Error while parsing provider %s: %s", sprov, err)
		} else {
			a.eventProvider.Filter.Update(&prov)
		}
	}

	// open traces
	for _, trace := range a.config.EtwConfig.UnifiedTraces() {
		if err := a.eventProvider.OpenTrace(trace); err != nil {
			a.logger.Errorf("Failed to open trace %s: %s", trace, err)
		}
	}

}

func (a *Agent) initHooks(advanced bool) {
	// We enable those hooks anyway since it is needed to skip
	// events generated by WHIDS process. These ar very light hooks
	a.preHooks.Hook(hookSelfGUID, fltProcessCreate)
	a.preHooks.Hook(hookProcTerm, fltProcTermination)
	a.preHooks.Hook(hookStats, fltStats)
	a.preHooks.Hook(hookTrack, fltTrack)

	if advanced {
		// Process terminator hook, terminating blacklisted (by action) processes
		a.preHooks.Hook(hookTerminator, fltProcessCreate)
		a.preHooks.Hook(hookImageLoad, fltImageLoad)
		a.preHooks.Hook(hookSetImageSize, fltImageSize)
		a.preHooks.Hook(hookProcessIntegrityProcTamp, fltImageTampering)
		a.preHooks.Hook(hookEnrichServices, fltAnySysmon)
		a.preHooks.Hook(hookClipboardEvents, fltClipboard)
		a.preHooks.Hook(hookFileSystemAudit, fltFSObjectAccess)
		// Must be run the last as it depends on other filters
		a.preHooks.Hook(hookEnrichAnySysmon, fltAnySysmon)
		a.preHooks.Hook(hookKernelFiles, fltKernelFile)

		// This hook must run before action handling as we want
		// the gene score to be set before an eventual reporting
		a.postHooks.Hook(hookUpdateGeneScore, fltAnyEvent)
	}
}

func (a *Agent) configureAuditPolicies() {
	c := a.config.AuditConfig

	if c.Enable {
		for _, ap := range c.AuditPolicies {
			if err := utils.EnableAuditPolicy(ap); err != nil {
				a.logger.Errorf("Failed to enable audit policy %s: %s", ap, err)
			} else {
				a.logger.Infof("Enabled Audit Policy: %s", ap)
			}
		}
	}

	// run this function async as it might take a little bit of time
	go func() {
		dirs := utils.StdDirs(utils.ExpandEnvs(c.AuditDirs...)...)
		if len(dirs) > 0 {
			a.logger.Infof("Setting ACLs for directories: %s", strings.Join(dirs, ", "))
			if err := utils.SetEDRAuditACL(dirs...); err != nil {
				a.logger.Errorf("Error while setting configured File System Audit ACLs: %s", err)
			}
			a.logger.Infof("Finished setting up ACLs for directories: %s", strings.Join(dirs, ", "))
		}
	}()
}

func (a *Agent) update(force bool) (last error) {
	var reloadRules, reloadContainers bool

	// check that we are connected to any manager
	if a.config.IsForwardingEnabled() {
		reloadRules = a.needsRulesUpdate()
		reloadContainers = a.needsIoCsUpdate()
	}

	// check if we need rule update
	if reloadRules {
		a.logger.Info("Updating WHIDS rules")
		if err := a.fetchRulesFromManager(); err != nil {
			a.logger.Errorf("Failed to fetch rules from manager: %s", err)
			reloadRules = false
		}
	}

	if reloadContainers {
		a.logger.Info("Updating WHIDS containers")
		if err := a.fetchIoCsFromManager(); err != nil {
			a.logger.Errorf("Failed to fetch containers from manager: %s", err)
			reloadContainers = false
		}
	}

	a.logger.Debugf("reloading rules:%t containers:%t forced:%t", reloadRules, reloadContainers, force)
	if reloadRules || reloadContainers || force {
		// We need to create a new engine if we received a rule/containers update
		newEngine := newActionnableEngine(a.config)

		// containers must be loaded before the rules anyway
		a.logger.Infof("Loading HIDS containers (used in rules) from: %s", a.config.RulesConfig.ContainersDB)
		if err := a.loadContainers(newEngine); err != nil {
			err = fmt.Errorf("failed at loading containers: %s", err)
			last = err
		}

		// Loading IOC container rules
		for _, rule := range IoCRules {
			if err := newEngine.LoadRule(&rule); err != nil {
				a.logger.Errorf("Failed to load IoC rule: %s", err)
				last = err
			}
		}

		// Loading canary rules
		if a.config.CanariesConfig.Enable {
			a.logger.Infof("Loading canary rules")
			// Sysmon rule
			sr := a.config.CanariesConfig.GenRuleSysmon()
			if err := newEngine.LoadRule(&sr); err != nil {
				a.logger.Errorf("Failed to load canary rule: %s", err)
				last = err
			}

			// File System Audit Rule
			fsr := a.config.CanariesConfig.GenRuleFSAudit()
			if err := newEngine.LoadRule(&fsr); err != nil {
				a.logger.Errorf("Failed to load canary rule: %s", err)
				last = err
			}

			// File System Audit Rule
			kfr := a.config.CanariesConfig.GenRuleKernelFile()
			if err := newEngine.LoadRule(&kfr); err != nil {
				a.logger.Errorf("Failed to load canary rule: %s", err)
				last = err
			}
		}

		// Loading rules
		a.logger.Infof("Loading HIDS rules from: %s", a.config.RulesConfig.RulesDB)
		if err := newEngine.LoadDirectory(a.config.RulesConfig.RulesDB); err != nil {
			last = fmt.Errorf("failed to load rules: %s", err)
		}
		a.logger.Infof("Number of rules loaded in engine: %d", newEngine.Count())

		// updating engine if no error
		if last == nil {
			// we update engine only if there was no error
			// no need to lock HIDS as newEngine is ready to use at this point
			a.Engine = newEngine
		} else {
			a.logger.Error("EDR engine not updated:", last)
		}
	} else {
		a.logger.Debug("Neither rules nor containers need to be updated")
	}

	return
}

// rules needs to be updated with the new ones available in manager
func (a *Agent) needsRulesUpdate() bool {
	var err error
	var oldSha256, sha256 string
	_, rulesSha256Path := a.config.RulesConfig.RulesPaths()

	// Don't need update if not connected to a manager
	if !a.config.IsForwardingEnabled() {
		return false
	}

	if sha256, err = a.forwarder.Client.GetRulesSha256(); err != nil {
		a.logger.Errorf("Failed to fetch rules sha256: %s", err)
		return false
	}

	oldSha256, _ = utils.ReadFileString(rulesSha256Path)

	// log message only if we need to update
	if oldSha256 != sha256 {
		a.logger.Infof("Rules: remote=%s local=%s", sha256, oldSha256)
	}

	return oldSha256 != sha256
}

// returns true if a container needs to be updated
func (a *Agent) needsIoCsUpdate() bool {
	var localSha256, remoteSha256 string

	// Don't need update if not connected to a manager
	if !a.config.IsForwardingEnabled() {
		return false
	}

	container := server.IoCContainerName
	_, locContSha256Path := a.containerPaths(container)

	// means that remoteCont is also a local container
	remoteSha256, _ = a.forwarder.Client.GetIoCsSha256()
	localSha256, _ = utils.ReadFileString(locContSha256Path)

	// log message only if we need to update
	if localSha256 != remoteSha256 {
		a.logger.Infof("container %s: remote=%s local=%s", container, remoteSha256, localSha256)
	}

	return localSha256 != remoteSha256
}

func (a *Agent) fetchRulesFromManager() (err error) {
	var rules, sha256 string

	rulePath, sha256Path := a.config.RulesConfig.RulesPaths()

	// if we are not connected to a manager we return
	if a.config.FwdConfig.Local {
		return
	}

	a.logger.Infof("Fetching new rules available in manager")
	if sha256, err = a.forwarder.Client.GetRulesSha256(); err != nil {
		return err
	}

	if rules, err = a.forwarder.Client.GetRules(); err != nil {
		return err
	}

	if sha256 != data.Sha256([]byte(rules)) {
		return fmt.Errorf("failed to verify rules integrity")
	}

	os.WriteFile(sha256Path, []byte(sha256), 0600)
	return os.WriteFile(rulePath, []byte(rules), 0600)
}

// containerPaths returns the path to the container and the path to its sha256 file
func (a *Agent) containerPaths(container string) (path, sha256Path string) {
	path = filepath.Join(a.config.RulesConfig.ContainersDB, fmt.Sprintf("%s%s", container, containerExt))
	sha256Path = fmt.Sprintf("%s.sha256", path)
	return
}

func (a *Agent) fetchIoCsFromManager() (err error) {
	var iocs []string
	cl := a.forwarder.Client

	// if we are not connected to a manager we return
	if a.config.FwdConfig.Local {
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
		return fmt.Errorf("failed to verify container \"%s\" integrity", server.IoCContainerName)
	}

	// we dump the container
	contPath, contSha256Path := a.containerPaths(server.IoCContainerName)
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
	return os.WriteFile(contSha256Path, []byte(compSha256), 0600)
}

// loads containers found in container database directory
func (a *Agent) loadContainers(engine *engine.Engine) (lastErr error) {
	for wi := range fswalker.Walk(a.config.RulesConfig.ContainersDB) {
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
				a.logger.Infof("Loading container %s from path %s", cont, path)
				if err = engine.LoadContainer(cont, r); err != nil {
					lastErr = fmt.Errorf("failed to load container %s: %s", cont, err)
					a.logger.Error(lastErr)
				}
				r.Close()
				fd.Close()
			}
		}
	}
	return
}

func (a *Agent) updateSystemInfo() (err error) {
	var hnew, hold string

	new := sysinfo.NewSystemInfo()
	if hnew, err = utils.Sha1Interface(new); err != nil {
		// we return cause we don't want to overwrite with
		// a faulty structure
		return
	}

	// if it returns an error we don't really care because
	// it will be replaced by new
	hold, _ = utils.Sha1Interface(a.systemInfo)

	if hnew != hold {
		a.systemInfo = new
		return a.forwarder.Client.PostSystemInfo(a.systemInfo)
	}

	return
}

/*
Warning: we cannot use binary hash information to decide wether we
need to update because Sysmon.exe (32 bit version) contains both the
32 and 64 bit version of the tool. When Sysmon gets installed only one
of the two versions is installed.
*/
func (a *Agent) updateSysmonBin() (err error) {
	var version string
	var si *sysmon.Info

	if si, err = sysmon.NewSysmonInfo(); err != nil {
		return
	}

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
	a.logger.Infof("Install/updating sysmon old=%s new=%s", si.Version, version)
	if err = sysmon.InstallOrUpdate(sysmonPath); err != nil {
		return fmt.Errorf("failed to install/update sysmon: %w", err)
	}

	// updating system information before config update as config update
	// may return on error
	if err = a.updateSystemInfo(); err != nil {
		return fmt.Errorf("failed to update system info: %w", err)
	}

	a.logger.Info("Updating sysmon config")
	// we update configuration
	if err = a.updateSysmonConfig(); err != nil {
		return fmt.Errorf("failed to update sysmon config: %w", err)
	}

	return
}

func (a *Agent) updateSysmonConfig() (err error) {
	var remoteSha256 string
	var xml []byte
	var cfg *sysmon.Config

	c := a.forwarder.Client
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

	case client.ErrNoSysmonConfig:
		// no configuration available on the manager

		a.logger.Info("No Sysmon config found on manager, trying to use default config")

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

	a.logger.Infof("Deploying new sysmon configuration old=%s new=%s", sha256, cfg.XmlSha256)
	if xml, err = cfg.XML(); err != nil {
		return
	}

	if err = sysmon.Configure(bytes.NewBuffer(xml)); err != nil {
		return fmt.Errorf("failed to configure sysmon: %w", err)
	}

	if err = a.updateSystemInfo(); err != nil {
		err = fmt.Errorf("failed to update system info: %w", err)
	}

	return
}

func (a *Agent) updateAgentConfig() (err error) {
	var newConf *config.Agent
	var localSha256, remoteSha256 string

	c := a.forwarder.Client

	if localSha256, err = a.config.Sha256(); err != nil {
		return fmt.Errorf("failed to compute local config sha256: %w", err)
	}

	remoteSha256, err = c.GetAgentConfigSha256()

	switch err {
	case nil:
		if localSha256 == remoteSha256 {
			// nothing to do
			return
		}

	case client.ErrNoAgentConfig:
		return c.PostAgentConfig(a.config)

	default:
		return
	}

	// we need to get configuration from manager
	if newConf, err = c.GetAgentConfig(); err != nil {
		return fmt.Errorf("failed to get agent config: %w", err)
	}

	a.logger.Infof("received endpoint configuration update old=%s new=%s, saving it at %s", localSha256, remoteSha256, a.config.Path())
	// overwrite current configuration
	newConf.Save(a.config.Path())

	a.logger.Infof("stopping agent after update")
	a.Stop()
	a.Wait()

	a.Initialize()
	if err = a.Prepare(newConf); err != nil {
		err = fmt.Errorf("failed to prepare agent with new configuration: %w", err)
		return
	}
	a.logger.Infof("restarting agent after update")
	a.Run()

	return
}

func (a *Agent) cleanup() {
	// Cleaning up empty dump directories if needed
	fis, _ := os.ReadDir(a.config.Dump.Dir)
	for _, fi := range fis {
		if fi.IsDir() {
			fp := filepath.Join(a.config.Dump.Dir, fi.Name())
			if utils.CountFiles(fp) == 0 {
				os.RemoveAll(fp)
			}
		}
	}
}

/** Public Methods **/

// IsHIDSEvent returns true if the event is generated by IDS activity
func (a *Agent) IsHIDSEvent(e *event.EdrEvent) bool {
	if pguid, ok := e.GetString(pathSysmonParentProcessGUID); ok {
		if pguid == a.guid {
			return true
		}
	}

	if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
		if guid == a.guid {
			return true
		}
		// search for parent in processTracker
		if pt := a.tracker.GetByGuid(guid); !pt.IsZero() {
			if pt.ParentProcessGUID == a.guid {
				return true
			}
		}
	}
	if sguid, ok := e.GetString(pathSysmonSourceProcessGUID); ok {
		if sguid == a.guid {
			return true
		}
		// search for parent in processTracker
		if pt := a.tracker.GetByGuid(sguid); !pt.IsZero() {
			if pt.ParentProcessGUID == a.guid {
				return true
			}
		}
	}
	return false
}

// Report generate a forensic ready report (meant to be dumped)
// this method is blocking as it runs commands and wait after those
func (a *Agent) Report(light bool) (r Report) {
	r.StartTime = time.Now()

	// generate a report for running processes or those terminated still having one child or more
	// do this step first not to polute report with commands to run
	r.Processes = a.tracker.PS()

	// Modules ever loaded
	r.Modules = a.tracker.Modules()

	// Drivers loaded
	r.Drivers = a.tracker.Drivers

	// if this is a light report, we don't run the commands
	if !light {
		// run all the commands configured to include in the report
		r.Commands = a.config.Report.PrepareCommands()
		for i := range r.Commands {
			r.Commands[i].Run()
		}
	}

	r.StopTime = time.Now()
	return
}

// Run starts the WHIDS engine and waits channel listening is stopped
func (a *Agent) Run() {

	// start task scheduler
	a.scheduler.Start()

	for _, t := range a.scheduler.Tasks() {
		a.logger.Infof("Scheduler running: %s", t.Name)
	}

	// Dry run don't do anything
	if a.DryRun {
		for _, trace := range a.config.EtwConfig.UnifiedTraces() {
			a.logger.Infof("Dry run: would open trace %s", trace)
		}
		return
	}

	// Starting event provider
	a.eventProvider.Start()

	// start stats monitoring
	a.stats.Start()

	a.waitGroup.Add(1)
	go func() {
		defer a.waitGroup.Done()

		// Trying to raise thread priority
		if err := kernel32.SetCurrentThreadPriority(win32.THREAD_PRIORITY_ABOVE_NORMAL); err != nil {
			a.logger.Errorf("Failed to raise IDS thread priority: %s", err)
		}

		for e := range a.eventProvider.Events {
			event := event.NewEdrEvent(e)

			if yes, eps := a.stats.HasPerfIssue(); yes {
				a.logger.Warnf("Average event rate above limit of %.2f e/s in the last %s: %.2f e/s", a.stats.Threshold(), a.stats.Duration(), eps)

				if a.stats.HasCriticalPerfIssue() {
					a.logger.Critical("Event throughput too high for too long, consider filtering out events")
				} else if crit := a.stats.CriticalEPS(); eps > crit {
					a.logger.Criticalf("Event throughput above %.0fx the limit, if repeated consider filtering out events", eps/a.stats.Threshold())
				}
			}

			// Warning message in certain circumstances
			if a.config.EnableHooks && !a.flagProcTermEn && a.stats.Events() > 0 && int64(a.stats.Events())%1000 == 0 {
				a.logger.Warn("Sysmon process termination events seem to be missing. WHIDS won't work as expected.")
			}

			a.RLock()

			// Runs pre detection hooks
			// putting this before next condition makes the processTracker registering
			// HIDS events and allows detecting ProcessAccess events from HIDS childs
			a.preHooks.RunHooksOn(a, event)

			// We skip if it is one of IDS event
			// we keep process termination event because it is used to control if process termination is enabled
			if a.IsHIDSEvent(event) && !isSysmonProcessTerminate(event) {
				if a.PrintAll {
					fmt.Println(utils.JsonStringOrPanic(event))
				}
				goto CONTINUE
			}

			// if event is skipped we don't log it even with PrintAll
			if event.IsSkipped() {
				a.stats.Update(event)
				goto CONTINUE
			}

			// if the event has matched at least one signature or is filtered
			if n, crit, filtered := a.Engine.MatchOrFilter(event); len(n) > 0 || filtered {
				switch {
				case crit >= a.config.CritTresh:
					if !a.PrintAll && !a.config.LogAll {
						a.forwarder.PipeEvent(event)
					}
					// Pipe the event to be sent to the forwarder
					// Run hooks post detection
					a.postHooks.RunHooksOn(a, event)
					a.stats.Update(event)
				case filtered && a.config.EnableFiltering && !a.PrintAll && !a.config.LogAll:
					//event.Del(&engine.GeneInfoPath)
					// we pipe filtered event
					a.forwarder.PipeEvent(event)
				}
			}

			// we queue event in action handler
			a.actionHandler.Queue(event)

			// Print everything
			if a.PrintAll {
				fmt.Println(utils.JsonStringOrPanic(event))
			}

			// We log all events
			if a.config.LogAll {
				a.forwarder.PipeEvent(event)
			}

			a.stats.Update(event)

		CONTINUE:
			a.RUnlock()
		}
		a.logger.Infof("HIDS main loop terminated")
	}()

	// Run bogus command so that at least one Process Terminate
	// is generated (used to check if process termination events are enabled)
	exec.Command(os.Args[0], "-h").Start()
}

// LogStats logs whids statistics
func (a *Agent) LogStats() {
	a.logger.Infof("Time Running: %s", a.stats.SinceStart())
	a.logger.Infof("Count Event Scanned: %.0f", a.stats.Events())
	a.logger.Infof("Average Event Rate: %.2f EPS", a.stats.EPS())
	a.logger.Infof("Alerts Reported: %.0f", a.stats.Detections())
	a.logger.Infof("Count Rules Used (loaded + generated): %d", a.Engine.Count())
}

// Stop stops the IDS
func (a *Agent) Stop() {
	a.logger.Infof("Stopping HIDS")
	// cancelling parent context
	a.cancel()
	// gently close forwarder needs to be done before
	// stop listening othewise we corrupt local logfiles
	// because of race condition
	a.logger.Infof("Closing forwarder")
	a.forwarder.Close()

	// closing event provider
	a.logger.Infof("Closing event provider")
	if err := a.eventProvider.Stop(); err != nil {
		a.logger.Errorf("Error while closing event provider: %s", err)
	}

	// cleaning canary files
	if a.config.CanariesConfig.Enable {
		a.logger.Infof("Cleaning canaries")
		a.config.CanariesConfig.Clean()
	}

	// updating autologger configuration
	a.logger.Infof("Updating autologger configuration")
	if err := config.Autologger.Delete(); err != nil {
		a.logger.Errorf("Failed to delete autologger: %s", err)
	}

	if err := a.config.EtwConfig.ConfigureAutologger(); err != nil {
		a.logger.Errorf("Failed to update autologger configuration: %s", err)
	}

	a.logger.Infof("HIDS stopped")
}

// Wait waits the IDS to finish
func (a *Agent) Wait() {
	a.waitGroup.Wait()
}

// WaitWithTimeout waits the IDS to finish
func (a *Agent) WaitWithTimeout(timeout time.Duration) {
	var slept time.Duration

	step := time.Millisecond * 25
	stop := make(chan bool)

	go func() {
		a.Wait()
		stop <- true
	}()

	for {
		select {
		case <-stop:
			return
		default:
			if slept >= timeout {
				return
			}
			time.Sleep(step)
			slept += step
		}
	}
}
