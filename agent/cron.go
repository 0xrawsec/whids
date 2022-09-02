package agent

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
	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/api/client"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/tools"
	"github.com/0xrawsec/whids/utils"
)

func (a *Agent) containCmd() *exec.Cmd {
	ip := a.forwarder.Client.ManagerIP
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

func (a *Agent) uncontainCmd() *exec.Cmd {
	return exec.Command("netsh.exe", "advfirewall",
		"firewall",
		"delete",
		"rule",
		fmt.Sprintf("name=%s", ContainRuleName),
	)
}

func (a *Agent) handleManagerCommand(cmd *api.EndpointCommand) {

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
		cmd.FromExecCmd(a.containCmd())

	/*
		@command: {
			"name": "uncontain",
			"description": "Uncontain host (i.e. remove network isolation)",
			"help": "`uncontain`"
		}
	*/
	case "uncontain":
		cmd.FromExecCmd(a.uncontainCmd())

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
		cmd.Json = a.Report(false)

	/*
		@command: {
			"name": "processes",
			"description": "Retrieve the full list of processes running (monitored from Sysmon logs)",
			"help": "`processes`"
		}
	*/
	case "processes":
		a.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = a.tracker.PS()
		a.tracker.RUnlock()

	/*
		@command: {
			"name": "modules",
			"description": "Retrieve the full list of modules ever loaded since boot (monitored from Sysmon logs)",
			"help": "`modules`"
		}
	*/
	case "modules":
		a.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = a.tracker.Modules()
		a.tracker.RUnlock()

	/*
		@command: {
			"name": "drivers",
			"description": "Retrieve the full list of drivers ever loaded since boot (monitored from Sysmon logs)",
			"help": "`drivers`"
		}
	*/
	case "drivers":
		a.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = a.tracker.Drivers
		a.tracker.RUnlock()
	}

	// we finally run the command
	if err := cmd.Run(); err != nil {
		a.logger.Errorf("failed to run command sent by manager \"%s\": %s", cmd.String(), err)
	}
}

////////////////// Tasks definition

// routine which manages command to be executed on the endpoint
// it is made in such a way that we can send burst of commands
func (a *Agent) taskCommandRunner() {
	defaultSleep := time.Second * 5
	sleep := defaultSleep

	burstDur := time.Duration(0)
	tgtBurstDur := time.Second * 30
	burstSleep := time.Millisecond * 500

	for {
		if cmd, err := a.forwarder.Client.FetchCommand(); err != nil && err != client.ErrNothingToDo {
			a.logger.Error(err)
		} else if err == nil {
			// reduce sleeping time if a command was received
			sleep = burstSleep
			burstDur = 0
			a.logger.Infof("[command runner] handling manager command: %s", cmd.String())
			a.handleManagerCommand(cmd)
			if err := a.forwarder.Client.PostCommand(cmd); err != nil {
				a.logger.Error("[command runner]", err)
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

func (a *Agent) scheduleCleanArchivedTask() error {
	if a.config.Sysmon.CleanArchived {
		archivePath := a.config.Sysmon.ArchiveDirectory

		if archivePath == "" {
			return errors.New("sysmon archive directory not configured")
		}

		if !fsutil.IsDir(archivePath) {
			return fmt.Errorf("no such Sysmon archive directory: %s", archivePath)
		}

		// to track already reported deletion errors
		reported := datastructs.NewSyncedSet()

		a.logger.Infof("Scheduling archive cleanup loop for directory: %s", archivePath)
		a.scheduler.Schedule(crony.NewTask("Sysmon archived files cleaner").Func(func() {
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
								a.logger.Error("[sysmon archived files cleaner]", "failed to remove archived file:", err)
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

func (a *Agent) taskUploadDumps() {
	// Sending dump files over to the manager
	for wi := range fswalker.Walk(a.config.Dump.Dir) {
		for _, fi := range wi.Files {
			sp := strings.Split(wi.Dirpath, string(os.PathSeparator))
			// upload only file with some extensions
			if uploadExts.Contains(filepath.Ext(fi.Name())) {
				if len(sp) >= 2 {
					var shrink *client.UploadShrinker
					var err error

					guid := sp[len(sp)-2]
					ehash := sp[len(sp)-1]
					fullpath := filepath.Join(wi.Dirpath, fi.Name())

					// we create upload shrinker object
					if shrink, err = client.NewUploadShrinker(fullpath, guid, ehash); err != nil {
						a.logger.Errorf("[dump uploader] failed to create upload iterator: %s", err)
						continue
					}

					if shrink.Size() > a.config.FwdConfig.Client.MaxUploadSize {
						a.logger.Warnf("[dump uploader] dump file is above allowed upload limit, %s will be deleted without being sent", fullpath)
						goto CleanShrinker
					}

					// we shrink a file into several chunks to reduce memory impact
					for fu := shrink.Next(); fu != nil; fu = shrink.Next() {
						if err = a.forwarder.Client.PostDump(fu); err != nil {
							a.logger.Error(err)
							break
						}
					}

				CleanShrinker:
					// close shrinker otherwise we cannot remove files
					shrink.Close()

					if shrink.Err() == nil {
						a.logger.Infof("[dump uploader] dump file successfully sent to manager, deleting: %s", fullpath)
						if err := os.Remove(fullpath); err != nil {
							a.logger.Errorf("[dump uploader] failed to remove file %s: %s", fullpath, err)
						}
					} else {
						a.logger.Errorf("[dump uploader] failed to post dump file: %s", shrink.Err())
					}
				} else {
					a.logger.Errorf("[dump uploader] unexpected directory layout, cannot send dump to manager")
				}
			}
		}
	}
}

func (a *Agent) updateTools() (err error) {
	var mtools map[string]*tools.Tool
	var locToolNames []string

	// getting the list of tools from the manager, only metatada are returned
	if mtools, err = a.forwarder.Client.ListTools(); err != nil {
		return
	}

	// updating local tools from remote
	for _, t := range mtools {
		var old *tools.Tool

		// if the tool is already there we continue
		if a.db.Search(&tools.Tool{}, "Metadata.Sha512", "=", t.Metadata.Sha512).Len() == 1 {
			continue
		}

		// we get the tool from manager
		if t, err = a.forwarder.Client.GetTool(t.Metadata.Sha256); err != nil {
			return
		}

		// search for a tool with the same name
		if err = a.db.Search(&tools.Tool{}, "Name", "=", t.Name).And("OS", "=", los.OS).AssignUnique(&old); err != nil && !sod.IsNoObjectFound(err) {
			return
		} else if err == nil {
			// we use same UUID not to duplicate entry
			t.Initialize(old.UUID())
		}

		// we update local database
		if err = a.db.InsertOrUpdate(t); err != nil {
			return
		}

		// dumping the tool on local folder
		if err = t.Dump(toolsDir); err != nil {
			return
		}
	}

	// We retrieve the names of the local files
	if err = a.db.AssignIndex(&tools.Tool{}, "Name", &locToolNames); err != nil {
		return
	}

	// deleting local tools
	for _, locName := range locToolNames {
		// if we have a tool locally that has been deleted from remote
		if _, ok := mtools[locName]; !ok {
			var t *tools.Tool
			s := a.db.Search(&tools.Tool{}, "Name", "=", locName)
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

func (a *Agent) scheduleTasks() {
	inLittleWhile := time.Now().Add(time.Second * 5)

	// routines scheduled only if connected to a manager
	if a.config.IsForwardingEnabled() {
		// High prio tasks

		// agent configuration update
		a.scheduler.Schedule(
			crony.NewTask("Configuration update").
				Func(func() {
					task := "[configuration update]"
					a.logger.Info(task, "update starting")
					if err := a.updateAgentConfig(); err != nil {
						a.logger.Error(task, err)
					}
				}).Ticker(time.Minute*15).
				Schedule(time.Now()),
			crony.PrioHigh,
		)

		// updating tools
		a.scheduler.Schedule(crony.NewTask("Utilities update").
			Func(func() {
				task := "[utilities update]"
				a.logger.Info(task, "update starting")
				if err := a.updateTools(); err != nil {
					a.logger.Error(task, err)
				}
			}).Ticker(time.Minute*15).
			Schedule(inLittleWhile),
			crony.PrioHigh)

		// updating engine
		a.scheduler.Schedule(crony.NewTask("Rule/IOC Update").
			Func(func() {
				task := "[rule/ioc update]"
				a.logger.Info(task, "update starting")
				if err := a.update(false); err != nil {
					a.logger.Error(task, err)
				}
			}).Ticker(a.config.RulesConfig.UpdateInterval).
			Schedule(inLittleWhile),
			crony.PrioHigh)

		// command runner routine, we run it only once as it creates a go routine to handle commands
		a.scheduler.Schedule(
			crony.NewAsyncTask("Command handler goroutine").
				Func(a.taskCommandRunner).
				Schedule(time.Now()),
			crony.PrioHigh)

		// Medium Prio Tasks

		// uploading dumps
		a.scheduler.Schedule(crony.NewTask("Upload Dump").
			Func(func() {
				task := "[upload dump]"
				a.logger.Info(task, "dump upload starting")
				a.taskUploadDumps()
				a.logger.Info(task, "dump upload done")
			}).Ticker(time.Minute).
			Schedule(time.Now()),
			crony.PrioMedium)

		// updating sysmon
		a.scheduler.Schedule(crony.NewTask("Sysmon update").
			Func(func() {
				task := "[sysmon update]"
				a.logger.Info(task, "update starting")
				if err := a.updateSysmonBin(); err != nil {
					a.logger.Error(task, err)
				}
			}).Ticker(time.Hour).
			Schedule(inLittleWhile),
			crony.PrioMedium)

		// updating sysmon configuration
		a.scheduler.Schedule(crony.NewTask("Sysmon configuration update").
			Func(func() {
				task := "[sysmon config update]"
				a.logger.Info(task, "update starting")
				if err := a.updateSysmonConfig(); err != nil {
					a.logger.Error(task, err)
				}
			}).Ticker(time.Minute*15).
			Schedule(inLittleWhile),
			crony.PrioMedium)

		// Low Prio Tasks

		// updating system information
		a.scheduler.Schedule(crony.NewTask("System Info Update").
			Func(func() {
				task := "[system info update]"
				a.logger.Info(task, "update starting")
				if err := a.updateSystemInfo(); err != nil {
					a.logger.Error(task, err)
				}
			}).Ticker(a.config.RulesConfig.UpdateInterval).
			Schedule(inLittleWhile),
			crony.PrioLow)

	}

	// routines scheduled in any case

	// Forwarder scheduling
	a.scheduler.Schedule(crony.NewTask("Log forwarder").
		Func(func() {
			// this call starts a new go routine so we don't need to create
			// a new AsyncTask as it is not a blocking call
			a.forwarder.Run()
		}).Schedule(time.Now()), crony.PrioHigh)

	// routine managing Sysmon archived files cleanup
	if err := a.scheduleCleanArchivedTask(); err != nil {
		a.logger.Error("failed to schedule sysmon archived file cleaning: ", err)
	}

	// routine creating canary files
	a.scheduler.Schedule(crony.NewAsyncTask("Canary configuration").
		Func(func() {
			task := "[canary configuration]"
			if err := a.config.CanariesConfig.Configure(); err != nil {
				a.logger.Error(task, err)
			}
		}).Schedule(time.Now()), crony.PrioHigh)

	// Action handler scheduling
	a.scheduler.Schedule(crony.NewAsyncTask("Action Handler").
		Func(func() {
			a.actionHandler.handleActionsLoop()
		}).Schedule(time.Now()), crony.PrioHigh)

	a.scheduler.Schedule(crony.NewAsyncTask("Action Handler File Compression").
		Func(func() {
			a.actionHandler.compressionLoop()
		}).Schedule(time.Now()), crony.PrioHigh)
}
