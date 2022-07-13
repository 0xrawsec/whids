package hids

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/crony"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/tools"
	"github.com/0xrawsec/whids/utils"
)

func (h *HIDS) containCmd() *exec.Cmd {
	ip := h.forwarder.Client.ManagerIP
	// only allow connection to the manager configured
	return exec.Command("netsh.exe",
		"advfirewall",
		"firewall",
		"add",
		"rule",
		fmt.Sprintf("name=%s", ContainRuleName),
		"dir=out",
		fmt.Sprintf("remoteip=0.0.0.0-%s,%s-255.255.255.255", utils.PrevIP(ip), utils.NextIP(ip)),
		"action=block")
}

func (h *HIDS) uncontainCmd() *exec.Cmd {
	return exec.Command("netsh.exe", "advfirewall",
		"firewall",
		"delete",
		"rule",
		fmt.Sprintf("name=%s", ContainRuleName),
	)
}

func (h *HIDS) handleManagerCommand(cmd *api.Command) {

	// command documentation template:
	/*
		// after copying the template remove #
		#@command: {
			"name": "cmd",
			"description": "Desc",
			"help": "cmd [OPTIONS...] MANDATORY",
			"example": "example"
		}
	*/

	// Switch processing the commands
	switch cmd.Name {

	// Aliases
	/*
		@command: {
				"name": "contain",
				"description": "Isolate host at network level",
				"help": "`contain`"
			}
	*/
	case "contain":
		cmd.FromExecCmd(h.containCmd())

	/*
		@command: {
			"name": "uncontain",
			"description": "Uncontain host (i.e. remove network isolation)",
			"help": "`uncontain`"
		}
	*/
	case "uncontain":
		cmd.FromExecCmd(h.uncontainCmd())

	/*
		@command: {
			"name": "osquery",
			"description": "Alias to `osqueryi --json -A`",
			"help": "`osquery OSQUERY_TABLE`",
			"example": "`osquery processes`"
		}
	*/
	case "osquery":
		// osquery alias
		cmd.Name = tools.ToolOSQueryi
		cmd.Args = append([]string{"--json", "-A"}, cmd.Args...)
		cmd.ExpectJSON = true

	/*
		@command: {
			"name": "sysmon",
			"description": "Alias to the sysmon binary deployed by the EDR. See sysmon binary command line switches for all available options.",
			"help": "`sysmon [OPTIONS]`",
			"example": "`sysmon -h`"
		}
	*/
	case "sysmon":
		// when installed, C:\\Windows\\ takes precedence over
		// the tool present in toolsDir
		cmd.Name = tools.ToolSysmon

	// internal commands
	/*
		@command: {
			"name": "terminate",
			"description": "Terminate a process given its PID",
			"help": "`terminate PID`",
			"example": "`terminate 1337`"
		}
	*/
	case "terminate":
		cmd.Unrunnable()
		if len(cmd.Args) > 0 {
			spid := cmd.Args[0]
			if pid, err := strconv.Atoi(spid); err != nil {
				cmd.ErrorFrom(fmt.Errorf("failed to parse pid: %w", err))
			} else if err := terminate(pid); err != nil {
				cmd.ErrorFrom(err)
			}
		}

	/*
		@command: {
			"name": "hash",
			"description": "Hash a file",
			"help": "`hash FILE`",
			"example": "`hash C:\\\\Windows\\\\System32\\\\cmd.exe`"
		}
	*/
	case "hash":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			if out, err := cmdHash(cmd.Args[0]); err != nil {
				cmd.ErrorFrom(err)
			} else {
				cmd.Json = out
			}
		}

	/*
		@command: {
			"name": "rexhash",
			"description": "Recursively find files matching pattern and hashes them",
			"help": "`rexhash DIRECTORY PATTERN`",
			"example": "`rexhash C:\\\\Windows\\\\System32 cmd\\\\.exe`"
		}
	*/
	case "rexhash":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) == 2 {
			if out, err := cmdFind(cmd.Args[0], cmd.Args[1], true); err != nil {
				cmd.ErrorFrom(err)
			} else {
				cmd.Json = out
			}
		}

	/*
		@command: {
			"name": "stat",
			"description": "Stat a file or a directory",
			"help": "`stat FILE|DIRECTORY`",
			"example": "`stat C:\\\\Windows\\\\System32\\\\cmd.exe`"
		}
	*/
	case "stat":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			if out, err := cmdStat(cmd.Args[0]); err != nil {
				cmd.ErrorFrom(err)
			} else {
				cmd.Json = out
			}
		}

	/*
		@command: {
			"name": "ls",
			"description": "List a directory",
			"help": "`ls DIRECTORY`",
			"example": "`ls C:\\\\Windows\\\\`"
		}
	*/
	case "ls":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			if out, err := cmdDir(cmd.Args[0]); err != nil {
				cmd.ErrorFrom(err)
			} else {
				cmd.Json = out
			}
		}

	/*
		@command: {
			"name": "walk",
			"description": "Recursively list a directory",
			"help": "`walk DIRECTORY`",
			"example": "`walk C:\\\\Windows\\\\System32`"
		}
	*/
	case "walk":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			cmd.Json = cmdWalk(cmd.Args[0])
		}

	/*
		@command: {
			"name": "find",
			"description": "Recursively find a pattern in filename",
			"help": "`find DIRECTORY REGEX_PATTERN`",
			"example": "`find C:\\\\Windows\\\\System32 cmd.*\\.exe`"
		}
	*/
	case "find":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) == 2 {
			if out, err := cmdFind(cmd.Args[0], cmd.Args[1], false); err != nil {
				cmd.ErrorFrom(err)
			} else {
				cmd.Json = out
			}
		}

	/*
		@command: {
			"name": "report",
			"description": "Generate a full IR ready report",
			"help": "`report`"
		}
	*/
	case "report":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.Report(false)

	/*
		@command: {
			"name": "processes",
			"description": "Retrieve the full list of processes running (monitored from Sysmon logs)",
			"help": "`processes`"
		}
	*/
	case "processes":
		h.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.tracker.PS()
		h.tracker.RUnlock()

	/*
		@command: {
			"name": "modules",
			"description": "Retrieve the full list of modules ever loaded since boot (monitored from Sysmon logs)",
			"help": "`modules`"
		}
	*/
	case "modules":
		h.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.tracker.Modules()
		h.tracker.RUnlock()

	/*
		@command: {
			"name": "drivers",
			"description": "Retrieve the full list of drivers ever loaded since boot (monitored from Sysmon logs)",
			"help": "`drivers`"
		}
	*/
	case "drivers":
		h.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.tracker.Drivers
		h.tracker.RUnlock()
	}

	// we finally run the command
	if err := cmd.Run(); err != nil {
		log.Errorf("failed to run command sent by manager \"%s\": %s", cmd.String(), err)
	}
}

////////////////// Tasks definition

// routine which manages command to be executed on the endpoint
// it is made in such a way that we can send burst of commands
func (h *HIDS) taskCommandRunner() {
	defaultSleep := time.Second * 5
	sleep := defaultSleep

	burstDur := time.Duration(0)
	tgtBurstDur := time.Second * 30
	burstSleep := time.Millisecond * 500

	for {
		if cmd, err := h.forwarder.Client.FetchCommand(); err != nil && err != api.ErrNothingToDo {
			log.Error(err)
		} else if err == nil {
			// reduce sleeping time if a command was received
			sleep = burstSleep
			burstDur = 0
			log.Infof("[command runner] handling manager command: %s", cmd.String())
			h.handleManagerCommand(cmd)
			if err := h.forwarder.Client.PostCommand(cmd); err != nil {
				log.Error("[command runner]", err)
			}
		}

		// if we reached the targetted burst duration
		if burstDur >= tgtBurstDur {
			sleep = defaultSleep
		}

		if sleep == burstSleep {
			burstDur += sleep
		}

		time.Sleep(sleep)
	}
}

func (h *HIDS) scheduleCleanArchivedTask() error {
	if h.config.Sysmon.CleanArchived {
		archivePath := h.config.Sysmon.ArchiveDirectory

		if archivePath == "" {
			return errors.New("sysmon archive directory not configured")
		}

		if !fsutil.IsDir(archivePath) {
			return fmt.Errorf("no such Sysmon archive directory: %s", archivePath)
		}

		// to track already reported deletion errors
		reported := datastructs.NewSyncedSet()

		log.Infof("Scheduling archive cleanup loop for directory: %s", archivePath)
		h.scheduler.Schedule(crony.NewTask("Sysmon archived files cleaner").Func(func() {
			// used to mark files for which we already reported errors
			// expiration fixed to five minutes
			expired := time.Now().Add(time.Minute * -5)
			for wi := range fswalker.Walk(archivePath) {
				for _, fi := range wi.Files {
					if archivedRe.MatchString(fi.Name()) {
						path := filepath.Join(wi.Dirpath, fi.Name())
						if fi.ModTime().Before(expired) {
							// we print out error only once
							if err := os.Remove(path); err != nil && !reported.Contains(path) {
								log.Error("[sysmon archived files cleaner]", "failed to remove archived file:", err)
								reported.Add(path)
							}
						}
					}
				}
			}
		}).Ticker(time.Minute), crony.PrioMedium)
	}

	return nil
}

func (h *HIDS) taskUploadDumps() {
	// Sending dump files over to the manager
	for wi := range fswalker.Walk(h.config.Dump.Dir) {
		for _, fi := range wi.Files {
			sp := strings.Split(wi.Dirpath, string(os.PathSeparator))
			// upload only file with some extensions
			if uploadExts.Contains(filepath.Ext(fi.Name())) {
				if len(sp) >= 2 {
					var shrink *api.UploadShrinker
					var err error

					guid := sp[len(sp)-2]
					ehash := sp[len(sp)-1]
					fullpath := filepath.Join(wi.Dirpath, fi.Name())

					// we create upload shrinker object
					if shrink, err = api.NewUploadShrinker(fullpath, guid, ehash); err != nil {
						log.Errorf("[dump uploader] failed to create upload iterator: %s", err)
						continue
					}

					if shrink.Size() > h.config.FwdConfig.Client.MaxUploadSize {
						log.Warnf("[dump uploader] dump file is above allowed upload limit, %s will be deleted without being sent", fullpath)
						goto CleanShrinker
					}

					// we shrink a file into several chunks to reduce memory impact
					for fu := shrink.Next(); fu != nil; fu = shrink.Next() {
						if err = h.forwarder.Client.PostDump(fu); err != nil {
							log.Error(err)
							break
						}
					}

				CleanShrinker:
					// close shrinker otherwise we cannot remove files
					shrink.Close()

					if shrink.Err() == nil {
						log.Infof("[dump uploader] dump file successfully sent to manager, deleting: %s", fullpath)
						if err := os.Remove(fullpath); err != nil {
							log.Errorf("[dump uploader] failed to remove file %s: %s", fullpath, err)
						}
					} else {
						log.Errorf("[dump uploader] failed to post dump file: %s", shrink.Err())
					}
				} else {
					log.Errorf("[dump uploader] unexpected directory layout, cannot send dump to manager")
				}
			}
		}
	}
}

func (h *HIDS) updateTools() (err error) {
	var mtools map[string]*tools.Tool
	var locToolNames []string

	// getting the list of tools from the manager, only metatada are returned
	if mtools, err = h.forwarder.Client.ListTools(); err != nil {
		return
	}

	// updating local tools from remote
	for _, t := range mtools {
		var old *tools.Tool

		// if the tool is already there we continue
		if h.db.Search(&tools.Tool{}, "Metadata.Sha512", "=", t.Metadata.Sha512).Len() == 1 {
			continue
		}

		// we get the tool from manager
		if t, err = h.forwarder.Client.GetTool(t.Metadata.Sha256); err != nil {
			return
		}

		// search for a tool with the same name
		if err = h.db.Search(&tools.Tool{}, "Name", "=", t.Name).And("OS", "=", los.OS).AssignUnique(&old); err != nil && !sod.IsNoObjectFound(err) {
			return
		} else if err == nil {
			// we use same UUID not to duplicate entry
			t.Initialize(old.UUID())
		}

		// we update local database
		if err = h.db.InsertOrUpdate(t); err != nil {
			return
		}

		// dumping the tool on local folder
		if err = t.Dump(toolsDir); err != nil {
			return
		}
	}

	// We retrieve the names of the local files
	if err = h.db.AssignIndex(&tools.Tool{}, "Name", &locToolNames); err != nil {
		return
	}

	// deleting local tools
	for _, locName := range locToolNames {
		// if we have a tool locally that has been deleted from remote
		if _, ok := mtools[locName]; !ok {
			var t *tools.Tool
			s := h.db.Search(&tools.Tool{}, "Name", "=", locName)
			if err = s.AssignUnique(&t); err != nil {
				return
			}

			if err = t.Remove(toolsDir); err != nil {
				return
			}

			if err = s.Delete(); err != nil {
				return
			}
		}
	}

	return
}

func (h *HIDS) scheduleTasks() {
	inLittleWhile := time.Now().Add(time.Second * 5)

	// routines scheduled only if connected to a manager
	if h.config.IsForwardingEnabled() {
		// command runner routine, we run it only once as it creates a go routine to handle commands
		h.scheduler.Schedule(
			crony.NewAsyncTask("Command handler goroutine").
				Func(h.taskCommandRunner).
				Schedule(time.Now()),
			crony.PrioHigh)

		// updating engine
		h.scheduler.Schedule(crony.NewTask("Rule/IOC Update").
			Func(func() {
				task := "[rule/ioc update]"
				log.Info(task, "update starting")
				if err := h.update(false); err != nil {
					log.Error(task, err)
				}
			}).Ticker(h.config.RulesConfig.UpdateInterval).Schedule(inLittleWhile),
			crony.PrioHigh)

		// uploading dumps
		h.scheduler.Schedule(crony.NewTask("Upload Dump").
			Func(h.taskUploadDumps).Ticker(time.Minute),
			crony.PrioMedium)

		// updating system information
		h.scheduler.Schedule(crony.NewTask("System Info Update").
			Func(func() {
				task := "[system info update]"
				log.Info(task, "update starting")
				if err := h.updateSystemInfo(); err != nil {
					log.Error(task, err)
				}
			}).Ticker(h.config.RulesConfig.UpdateInterval).
			Schedule(inLittleWhile),
			crony.PrioLow)

		// updating sysmon
		h.scheduler.Schedule(crony.NewTask("Sysmon update").
			Func(func() {
				task := "[sysmon update]"
				log.Info(task, "update starting")
				if err := h.updateSysmon(); err != nil {
					log.Error(task, err)
				}
			}).Ticker(time.Hour).Schedule(inLittleWhile),
			crony.PrioMedium)

		// updating sysmon configuration
		h.scheduler.Schedule(crony.NewTask("Sysmon configuration update").
			Func(func() {
				task := "[sysmon config update]"
				log.Info(task, "update starting")
				if err := h.updateSysmonConfig(); err != nil {
					log.Error(task, err)
				}
			}).Ticker(time.Minute*15).Schedule(inLittleWhile),
			crony.PrioMedium)

		// updating tools
		h.scheduler.Schedule(crony.NewTask("Utilities update").
			Func(func() {
				task := "[utilities update]"
				log.Info(task, "update starting")
				if err := h.updateTools(); err != nil {
					log.Error(task, err)
				}
			}).Ticker(time.Minute*15).Schedule(inLittleWhile),
			crony.PrioHigh)
	}

	// routines scheduled in any case

	// routine managing Sysmon archived files cleanup
	if err := h.scheduleCleanArchivedTask(); err != nil {
		log.Error("failed to schedule sysmon archived file cleaning: ", err)
	}

	// routine creating canary files
	h.scheduler.Schedule(crony.NewAsyncTask("Canary configuration").Func(func() {
		task := "[canary configuration]"
		if err := h.config.CanariesConfig.Configure(); err != nil {
			log.Error(task, err)
		}
	}).Schedule(time.Now()), crony.PrioHigh)

	h.scheduler.Schedule(crony.NewAsyncTask("Action Handler").Func(func() {
		h.actionHandler.handleActionsLoop()
	}).Schedule(time.Now()), crony.PrioHigh)

	h.scheduler.Schedule(crony.NewAsyncTask("Action Handler File Compression").Func(func() {
		h.actionHandler.compressionLoop()
	}).Schedule(time.Now()), crony.PrioHigh)

	h.scheduler.Start()
}
