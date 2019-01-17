package main

import (
	"fmt"
	"hooks"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"utils"

	"github.com/0xrawsec/golang-utils/crypto/data"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/sync/semaphore"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/dbghelp"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

////////////////////////////////// Hooks //////////////////////////////////

var (
	// DNSFilter filters any Windows-DNS-Client log
	dnsFilter = hooks.NewFilter([]int64{}, []string{"Microsoft-Windows-DNS-Client/Operational"})
	// SysmonNetConnFilter filters any Sysmon network connection
	sysmonNetConnFilter   = hooks.NewFilter([]int64{3}, []string{"Microsoft-Windows-Sysmon/Operational"})
	sysmonEventsWithImage = hooks.NewFilter([]int64{1, 6, 7}, []string{"Microsoft-Windows-Sysmon/Operational"})
	sysmonProcTermination = hooks.NewFilter([]int64{5}, []string{"Microsoft-Windows-Sysmon/Operational"})
	statFilter            = hooks.NewFilter([]int64{1, 3, 11}, []string{"Microsoft-Windows-Sysmon/Operational"})
	dumpFileFilter        = hooks.NewFilter([]int64{1, 2, 6, 11, 13, 15, 20}, []string{"Microsoft-Windows-Sysmon/Operational"})
	anySysmonEvent        = hooks.NewFilter([]int64{}, []string{"Microsoft-Windows-Sysmon/Operational"})

	dnsQueryValue   = evtx.Path("/Event/EventData/QueryName")
	dnsQueryType    = evtx.Path("/Event/EventData/QueryType")
	dnsQueryResults = evtx.Path("/Event/EventData/QueryResults")

	// Sysmon related paths
	sysmonDestIP            = evtx.Path("/Event/EventData/DestinationIp")
	sysmonDestHostname      = evtx.Path("/Event/EventData/DestinationHostname")
	sysmonImage             = evtx.Path("/Event/EventData/Image")
	sysmonCommandLine       = evtx.Path("/Event/EventData/CommandLine")
	sysmonParentImage       = evtx.Path("/Event/EventData/ParentImage")
	sysmonImageLoaded       = evtx.Path("/Event/EventData/ImageLoaded")
	sysmonSourceProcessGUID = evtx.Path("/Event/EventData/SourceProcessGUID")
	sysmonProcessGUID       = evtx.Path("/Event/EventData/ProcessGuid")
	sysmonParentProcessGUID = evtx.Path("/Event/EventData/ParentProcessGuid")
	sysmonParentProcessId   = evtx.Path("/Event/EventData/ParentProcessId")
	sysmonProcessId         = evtx.Path("/Event/EventData/ProcessId")
	sysmonSourceProcessId   = evtx.Path("/Event/EventData/SourceProcessId")
	sysmonTargetFilename    = evtx.Path("/Event/EventData/TargetFilename")
	sysmonCurrentDirectory  = evtx.Path("/Event/EventData/CurrentDirectory")
	sysmonDetails           = evtx.Path("/Event/EventData/Details")
	sysmonDestination       = evtx.Path("/Event/EventData/Destination")

	// Gene criticality path
	geneCriticality = evtx.Path("/Event/GeneInfo/Criticality")

	// Use to store image sizes information by hook
	imSizePath       = evtx.Path("/Event/EventData/ImageSize")
	imLoadedSizePath = evtx.Path("/Event/EventData/ImageLoadedSize")

	// Use to store process information by hook
	parentIntegrity  = evtx.Path("/Event/EventData/ParentProcessIntegrity")
	processIntegrity = evtx.Path("/Event/EventData/ProcessIntegrity")
	integrityTimeout = evtx.Path("/Event/EventData/IntegrityTimeout")

	// map mapping ip to domains
	dnsResolution = make(map[string]string)

	// map of processStats key: GUID
	processTracker = make(map[string]*processTrack)

	blacklistedImages = datastructs.NewSyncedSet()

	terminated = datastructs.NewSyncedSet()

	memdumped  = datastructs.NewSyncedSet()
	memdumping = datastructs.NewSyncedSet()

	parallelHooks = semaphore.New(4)

	compressionIsRunning = false
	compressionChannel   = make(chan string)
)

type stats struct {
	CountProcessCreated    int64
	CountNetConn           int64
	CountFilesCreated      int64
	CountFilesCreatedByExt map[string]*int64
}

type processTrack struct {
	Image             string
	PID               int64
	CommandLine       string
	ProcessGUID       string
	ParentProcessGUID string
	Stats             stats
	MemDumped         bool
}

func toString(i interface{}) string {
	return fmt.Sprintf("%v", i)
}

// helper function which checks if the event belongs to current WHIDS
func isSelf(e *evtx.GoEvtxMap) bool {
	if pguid, err := e.GetString(&sysmonParentProcessGUID); err == nil {
		if pguid == selfGUID {
			return true
		}
	}
	if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
		if guid == selfGUID {
			return true
		}
	}
	if sguid, err := e.GetString(&sysmonSourceProcessGUID); err == nil {
		if sguid == selfGUID {
			return true
		}
	}
	return false
}

// hook applying on Sysmon events containing image information and
// adding a new field containing the image size
func hookSetImageSize(e *evtx.GoEvtxMap) {
	var path *evtx.GoEvtxPath
	var modpath *evtx.GoEvtxPath
	switch e.EventID() {
	case 1:
		path = &sysmonImage
		modpath = &imSizePath
	default:
		path = &sysmonImageLoaded
		modpath = &imLoadedSizePath
	}
	if image, err := e.GetString(path); err == nil {
		if fsutil.IsFile(image) {
			if stat, err := os.Stat(image); err == nil {
				e.Set(modpath, toString(stat.Size()))
			}
		}
	}
}

// hooks Windows DNS client logs and maintain a domain name resolution table
func hookDNS(e *evtx.GoEvtxMap) {
	if qtype, err := e.GetInt(&dnsQueryType); err == nil {
		// request for A or AAAA records
		if qtype == 1 || qtype == 28 {
			if qresults, err := e.GetString(&dnsQueryResults); err == nil {
				if qresults != "" {
					records := strings.Split(qresults, ";")
					for _, r := range records {
						// check if it is a valid IP
						if net.ParseIP(r) != nil {
							if qvalue, err := e.GetString(&dnsQueryValue); err == nil {
								dnsResolution[r] = qvalue
							}
						}
					}
				}
			}
		}
	}
}

// hook tracking processes
func hookTrack(e *evtx.GoEvtxMap) {
	// We need to be sure that process termination is enabled
	// before initiating process tracking not to fill up memory
	// with never freed data
	if e.EventID() == 1 && flagProcTermEn {
		if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
			if pid, err := e.GetInt(&sysmonProcessId); err == nil {
				if image, err := e.GetString(&sysmonImage); err == nil {
					if commandLine, err := e.GetString(&sysmonCommandLine); err == nil {
						if pguid, err := e.GetString(&sysmonParentProcessGUID); err == nil {
							processTracker[guid] = &processTrack{
								Image:             image,
								CommandLine:       commandLine,
								PID:               pid,
								ProcessGUID:       guid,
								ParentProcessGUID: pguid,
								Stats:             stats{0, 0, 0, make(map[string]*int64)},
							}
						}
					}
				}
			}
		}
	}
}

// hook making statistics about process created
func hookStats(e *evtx.GoEvtxMap) {
	// We do not store stats if process termination is not enabled
	if flagProcTermEn {
		if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
			pt := processTracker[guid]
			if pt != nil {
				switch e.EventID() {
				case 1:
					pt.Stats.CountProcessCreated++
				case 3:
					pt.Stats.CountNetConn++
				case 11:
					if target, err := e.GetString(&sysmonTargetFilename); err == nil {
						ext := filepath.Ext(target)
						if pt.Stats.CountFilesCreatedByExt[ext] == nil {
							i := int64(0)
							pt.Stats.CountFilesCreatedByExt[ext] = &i
						}
						*(pt.Stats.CountFilesCreatedByExt[ext])++
					}
					pt.Stats.CountFilesCreated++
				}
			}
		}
	}
}

func terminator(pid int) error {
	pHandle, err := kernel32.OpenProcess(kernel32.PROCESS_ALL_ACCESS, win32.FALSE, win32.DWORD(pid))
	if err != nil {
		return err
	}
	err = syscall.TerminateProcess(syscall.Handle(pHandle), 0)
	if err != nil {
		return err
	}
	return nil
}

// hook implementing protection against cryptolockers
func hookCryptoProtect(e *evtx.GoEvtxMap) {
	if e.EventID() == 11 {
		if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
			pt := processTracker[guid]
			if pt != nil && !terminated.Contains(guid) {
				if target, err := e.GetString(&sysmonTargetFilename); err == nil {
					ext := filepath.Ext(target)
					cnt := pt.Stats.CountFilesCreatedByExt[ext]
					if cnt != nil && !isWhitelistedExt(ext) {
						if *cnt > cryptoLockerFilecreateLimit {
							if pid, err := e.GetInt(&sysmonProcessId); err == nil {
								log.Warnf("Crypto-Locker prevention triggered, process is being terminated: PID=%d Image=\"%s\" Ext=\"%s\"",
									pt.PID, pt.Image, ext)
								if err := terminator(int(pid)); err != nil {
									log.Errorf("Failed to terminate process PID=%d: %s", pt.PID, err)
								} else {
									blacklistedImages.Add(pt.CommandLine)
									terminated.Add(guid)
								}
							}
						}
					}
				}
			}
		}
	}
}

// hook terminating previously blacklisted processes (according to their CommandLine)
func hookTerminator(e *evtx.GoEvtxMap) {
	if e.EventID() == 1 {
		if commandLine, err := e.GetString(&sysmonCommandLine); err == nil {
			if pid, err := e.GetInt(&sysmonProcessId); err == nil {
				if blacklistedImages.Contains(commandLine) {
					log.Warnf("Terminating blacklisted  process PID=%d CommandLine=\"%s\"", pid, commandLine)
					if err := terminator(int(pid)); err != nil {
						log.Errorf("Failed to terminate process PID=%d: %s", pid, err)
					}
				}
			}
		}
	}
}

// hook setting flagProcTermEn variable
// it is also used to cleanup any structures needing to be cleaned
func hookProcTerm(e *evtx.GoEvtxMap) {
	log.Debug("Process termination events are enabled")
	flagProcTermEn = true
	if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
		// We clean up data structures
		delete(processTracker, guid)
		terminated.Del(guid)
		// cleaning memory dumped process
		memdumped.Del(guid)
	}
}

// hook that replaces the destination hostname of Sysmon Network connection
// event with the one previously found in the DNS logs
func hookNetConn(e *evtx.GoEvtxMap) {
	if ip, err := e.GetString(&sysmonDestIP); err == nil {
		if dom, ok := dnsResolution[ip]; ok {
			e.Set(&sysmonDestHostname, dom)
		}
	}
}

func hookSelfGUID(e *evtx.GoEvtxMap) {
	if selfGUID == "" {
		if e.EventID() == 1 {
			// Sometimes it happens that other events are generated before process creation
			// Check parent image first because we launch whids.exe -h to test process termination
			// and we catch it up if we check image first
			if pimage, err := e.GetString(&sysmonParentImage); err == nil {
				if pimage == selfPath {
					if pguid, err := e.GetString(&sysmonParentProcessGUID); err == nil {
						selfGUID = pguid
						log.Infof("Found self GUID from PGUID: %s", selfGUID)
						return
					}
				}
			}
			if image, err := e.GetString(&sysmonImage); err == nil {
				if image == selfPath {
					if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
						selfGUID = guid
						//log.Infof("Found self GUID: %s", selfGUID)
						log.Infof("Found self GUID: %s", string(evtx.ToJSON(e)))
						return
					}
				}
			}
		}
	}
}

func hookProcessIntegrity(e *evtx.GoEvtxMap) {
	// Sysmon Create Process
	if e.EventID() == 1 {
		// Default values
		e.Set(&parentIntegrity, toString(-1.0))
		e.Set(&processIntegrity, toString(-1.0))
		e.Set(&integrityTimeout, toString(false))

		if ppid, err := e.GetInt(&sysmonParentProcessId); err == nil {
			if kernel32.IsPIDRunning(int(ppid)) {
				da := win32.DWORD(kernel32.PROCESS_VM_READ | kernel32.PROCESS_QUERY_INFORMATION)
				hProcess, err := kernel32.OpenProcess(da, win32.FALSE, win32.DWORD(ppid))
				if err != nil {
					log.Errorf("Cannot open parent process to check integrity PPID=%d: %s", ppid, err)
				} else {
					defer kernel32.CloseHandle(hProcess)
					bdiff, slen, err := kernel32.CheckProcessIntegrity(hProcess)
					if err != nil {
						log.Errorf("Cannot check integrity of parent PPID=%d: %s", ppid, err)
					} else {
						if slen != 0 {
							e.Set(&parentIntegrity, toString(utils.Round(float64(bdiff)*100/float64(slen), 2)))
						}
					}
				}
			} else {
				log.Warnf("Cannot check integrity of parent PPID=%d: process terminated", ppid)
			}
		}

		if pid, err := e.GetInt(&sysmonProcessId); err == nil {
			if kernel32.IsPIDRunning(int(pid)) {
				// we first need to wait main process thread
				mainTid := kernel32.GetFirstTidOfPid(int(pid))
				// if we found the main thread of pid
				if mainTid > 0 {
					hThread, err := kernel32.OpenThread(kernel32.THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(mainTid))
					if err != nil {
						log.Errorf("Cannot open main thread before checking integrity of PID=%d", pid)
					} else {
						defer kernel32.CloseHandle(hThread)
						if ok := kernel32.WaitThreadRuns(hThread, time.Millisecond*50, time.Millisecond*500); !ok {
							// We check whether the thread still exists
							checkThread, err := kernel32.OpenThread(kernel32.PROCESS_SUSPEND_RESUME, win32.FALSE, win32.DWORD(mainTid))
							if err == nil {
								log.Warnf("Timeout reached while waiting main thread of PID=%d", pid)
								e.Set(&integrityTimeout, toString(true))
							}
							kernel32.CloseHandle(checkThread)
						} else {
							da := win32.DWORD(kernel32.PROCESS_VM_READ | kernel32.PROCESS_QUERY_INFORMATION)
							hProcess, err := kernel32.OpenProcess(da, win32.FALSE, win32.DWORD(pid))

							if err != nil {
								log.Errorf("Cannot open process to check integrity of PID=%d: %s", pid, err)
							} else {
								defer kernel32.CloseHandle(hProcess)
								bdiff, slen, err := kernel32.CheckProcessIntegrity(hProcess)
								if err != nil {
									log.Errorf("Cannot check integrity of PID=%d: %s", pid, err)
								} else {
									if slen != 0 {
										e.Set(&processIntegrity, toString(utils.Round(float64(bdiff)*100/float64(slen), 2)))
									}
								}
							}
						}
					}
				}
			} else {

				log.Warnf("Cannot check integrity of PID=%d: process terminated", pid)
			}
		}
	}
}

//////////////////// Hooks' helpers /////////////////////

func getCriticality(e *evtx.GoEvtxMap) int {
	if c, err := e.Get(&geneCriticality); err == nil {
		return (*c).(int)
	}
	return 0
}

func compress(path string) {
	if flagDumpCompress {
		if !compressionIsRunning {
			// start compression routine
			go func() {
				compressionIsRunning = true
				for path := range compressionChannel {
					log.Infof("Compressing %s", path)
					if err := utils.GzipFile(path); err != nil {
						log.Errorf("Cannot compress %s: %s", path, err)
					}
				}
				compressionIsRunning = false
			}()
		}
		compressionChannel <- path
	}
}

func dumpPid(pid int, guid, id string) {
	// prevent stopping ourself (><)
	if kernel32.IsPIDRunning(pid) && pid != selfPid && !memdumped.Contains(guid) && !memdumping.Contains(guid) {
		//kernel32.SuspendProcess(int(pid))
		//defer kernel32.ResumeProcess(int(pid))

		// To avoid dumping the same process twice, possible if two alerts
		// comes from the same GUID in a short period of time
		memdumping.Add(guid)
		defer memdumping.Del(guid)

		tmpDumpDir := filepath.Join(dumpDirectory, guid, id)
		os.MkdirAll(tmpDumpDir, defaultPerms)
		module, err := kernel32.GetModuleFilenameFromPID(int(pid))
		if err != nil {
			log.Errorf("Cannot get module filename for memory dump PID=%d: %s", pid, err)
		}
		dumpFilename := fmt.Sprintf("%s_%d_%d.dmp", filepath.Base(module), pid, time.Now().Unix())
		dumpPath := filepath.Join(tmpDumpDir, dumpFilename)
		log.Infof("Trying to dump memory of process PID=%d Image=\"%s\"", pid, module)
		//log.Infof("Mock dump: %s", dumpFilename)
		err = dbghelp.FullMemoryMiniDump(pid, dumpPath)
		if err != nil {
			log.Errorf("Failed to dump process PID=%d Image=%s: %s", pid, module, err)
		} else {
			// dump was successfull
			memdumped.Add(guid)
			compress(dumpPath)
		}
	} else {
		log.Warnf("Cannot dump process PID=%d, the process is already terminated", pid)
	}

}

func dumpFileAndCompress(src, path string) error {
	os.MkdirAll(path, defaultPerms)
	// replace : in case we are dumping an ADS
	base := strings.Replace(filepath.Base(src), ":", "_ADS_", -1)
	dst := filepath.Join(path, fmt.Sprintf("%d_%s.bin", time.Now().Unix(), base))
	log.Debugf("Dumping file: %s->%s", src, dst)
	err := fsutil.CopyFile(src, dst)
	if err == nil {
		compress(dst)
	}
	return err
}

func idFromEvent(e *evtx.GoEvtxMap) string {
	bs := utils.ByteSlice(evtx.ToJSON(e))
	sort.Stable(bs)
	return data.Md5(bs)
}

func dumpEventAndCompress(e *evtx.GoEvtxMap, guid string) (err error) {
	id := idFromEvent(e)
	tmpDumpDir := filepath.Join(dumpDirectory, guid, id)
	os.MkdirAll(tmpDumpDir, defaultPerms)
	dumpPath := filepath.Join(tmpDumpDir, fmt.Sprintf("%s_event.json", id))
	f, err := os.Create(dumpPath)
	if err != nil {
		return
	}
	f.Write(evtx.ToJSON(e))
	f.Close()
	compress(dumpPath)
	return
}

//////////////////// Post Detection Hooks /////////////////////

// this hook can run async
func hookDumpProcess(e *evtx.GoEvtxMap) {
	// we dump only if alert is relevant
	if getCriticality(e) < dumpTresh {
		return
	}

	parallelHooks.Acquire()
	go func() {
		defer parallelHooks.Release()
		var pidPath *evtx.GoEvtxPath
		var procGUIDPath *evtx.GoEvtxPath

		// the interesting pid to dump depends on the event
		switch e.EventID() {
		case 8, 10:
			pidPath = &sysmonSourceProcessId
			procGUIDPath = &sysmonSourceProcessGUID
		default:
			pidPath = &sysmonProcessId
			procGUIDPath = &sysmonProcessGUID
		}

		if guid, err := e.GetString(procGUIDPath); err == nil {
			if pid, err := e.GetInt(pidPath); err == nil {
				dumpEventAndCompress(e, guid)
				dumpPid(int(pid), guid, idFromEvent(e))
			}
		}

	}()
}

func hookDumpFile(e *evtx.GoEvtxMap) {
	// we dump only if alert is relevant
	if getCriticality(e) < dumpTresh {
		return
	}

	parallelHooks.Acquire()
	go func() {
		defer parallelHooks.Release()
		guid := "{UNKNOWN_GUID}"
		if tmpGUID, err := e.GetString(&sysmonProcessGUID); err == nil {
			guid = tmpGUID
		}
		dumpPath := filepath.Join(dumpDirectory, guid, idFromEvent(e))
		dumpEventAndCompress(e, guid)

		switch e.EventID() {
		case 1:
			if cl, err := e.GetString(&sysmonCommandLine); err == nil {
				if cwd, err := e.GetString(&sysmonCurrentDirectory); err == nil {
					if argv, err := utils.ArgvFromCommandLine(cl); err == nil {
						if len(argv) > 1 {
							for _, arg := range argv[1:] {
								if fsutil.IsFile(arg) && !utils.IsPipePath(arg) {
									if err = dumpFileAndCompress(arg, dumpPath); err != nil {
										log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), arg, err)
									}
								}
								// try to dump a path relative to CWD
								relarg := filepath.Join(cwd, arg)
								if fsutil.IsFile(relarg) && !utils.IsPipePath(relarg) {
									if err = dumpFileAndCompress(relarg, dumpPath); err != nil {
										log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), relarg, err)
									}
								}
							}
						}
					}
				}
			}
			if im, err := e.GetString(&sysmonImage); err == nil {
				if err = dumpFileAndCompress(im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}
			if pim, err := e.GetString(&sysmonParentImage); err == nil {
				if err = dumpFileAndCompress(pim, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), pim, err)
				}
			}
		case 2, 11, 15:
			if target, err := e.GetString(&sysmonTargetFilename); err == nil {
				if err = dumpFileAndCompress(target, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), target, err)
				}
			}
		case 6:
			if im, err := e.GetString(&sysmonImageLoaded); err == nil {
				if err = dumpFileAndCompress(im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}
		case 13, 20:
			path := &sysmonDetails
			if e.EventID() == 13 {
				path = &sysmonDestination
			}
			if cl, err := e.GetString(path); err == nil {
				// try to parse details as a command line
				if argv, err := utils.ArgvFromCommandLine(cl); err == nil {
					for _, arg := range argv {
						if fsutil.IsFile(arg) && !utils.IsPipePath(arg) {
							if err = dumpFileAndCompress(arg, dumpPath); err != nil {
								log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), arg, err)
							}
						}
					}
				}
			}
		}
	}()
}
