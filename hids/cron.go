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
	"github.com/0xrawsec/whids/api"
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

	// Switch processing the commands
	switch cmd.Name {
	// Aliases
	case "contain":
		cmd.FromExecCmd(h.containCmd())
	case "uncontain":
		cmd.FromExecCmd(h.uncontainCmd())
	case "osquery":
		osquery := h.config.Report.OSQuery.Bin
		switch {
		case fsutil.IsFile(h.config.Report.OSQuery.Bin):
			cmd.Name = h.config.Report.OSQuery.Bin
			cmd.Args = append([]string{"--json", "-A"}, cmd.Args...)
			cmd.ExpectJSON = true
		case osquery == "":
			cmd.Unrunnable()
			cmd.Error = "OSQuery binary file configured does not exist"
		default:
			cmd.Unrunnable()
			cmd.Error = fmt.Sprintf("OSQuery binary file configured does not exist: %s", osquery)
		}

	// internal commands
	case "terminate":
		cmd.Unrunnable()
		if len(cmd.Args) > 0 {
			spid := cmd.Args[0]
			if pid, err := strconv.Atoi(spid); err != nil {
				cmd.Error = fmt.Sprintf("failed to parse pid: %s", err)
			} else if err := terminate(pid); err != nil {
				cmd.Error = err.Error()
			}
		}
	case "hash":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			if out, err := cmdHash(cmd.Args[0]); err != nil {
				cmd.Error = err.Error()
			} else {
				cmd.Json = out
			}
		}
	case "stat":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			if out, err := cmdStat(cmd.Args[0]); err != nil {
				cmd.Error = err.Error()
			} else {
				cmd.Json = out
			}
		}
	case "dir":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			if out, err := cmdDir(cmd.Args[0]); err != nil {
				cmd.Error = err.Error()
			} else {
				cmd.Json = out
			}
		}
	case "walk":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) > 0 {
			cmd.Json = cmdWalk(cmd.Args[0])
		}
	case "find":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		if len(cmd.Args) == 2 {
			if out, err := cmdFind(cmd.Args[0], cmd.Args[1]); err != nil {
				cmd.Error = err.Error()
			} else {
				cmd.Json = out
			}
		}
	case "report":
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.Report(false)
	case "processes":
		h.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.tracker.PS()
		h.tracker.RUnlock()
	case "modules":
		h.tracker.RLock()
		cmd.Unrunnable()
		cmd.ExpectJSON = true
		cmd.Json = h.tracker.Modules()
		h.tracker.RUnlock()
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

func (h *HIDS) scheduleTasks() {
	if h.config.IsForwardingEnabled() {
		// command runner routine, we run it only once as it creates a go routine to handle commands
		h.scheduler.Schedule(crony.NewAsyncTask("Command handler goroutine").Func(h.taskCommandRunner).Schedule(time.Now()), crony.PrioHigh)

		// updating engine
		h.scheduler.Schedule(crony.NewTask("Rule/IOC Update").Func(func() {
			if err := h.update(false); err != nil {
				log.Error("[rule/ioc update]", err)
			}
		}).Ticker(h.config.RulesConfig.UpdateInterval), crony.PrioHigh)

		// uploading dumps
		h.scheduler.Schedule(crony.NewTask("Upload Dump").Func(h.taskUploadDumps).Ticker(time.Minute), crony.PrioMedium)

		// updating system information
		h.scheduler.Schedule(crony.NewTask("System Info Update").Func(func() {
			if err := h.updateSystemInfo(); err != nil {
				log.Error("[system info update]", err)
			}
		}).Ticker(h.config.RulesConfig.UpdateInterval), crony.PrioLow)

		// updating sysmon configuration
		h.scheduler.Schedule(crony.NewTask("Sysmon configuration update").Func(func() {
			if err := h.updateSysmonConfig(); err != nil {
				log.Error("[sysmon config update]", err)
			}
		}).Ticker(time.Minute*15), crony.PrioMedium)
	}

	if err := h.scheduleCleanArchivedTask(); err != nil {
		log.Error("failed to schedule sysmon archived file cleaning: ", err)
	}

	h.scheduler.Start()
}
