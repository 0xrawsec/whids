package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/file"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/sync/semaphore"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/golang-win32/win32/dbghelp"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/hooks"
	"github.com/0xrawsec/whids/utils"
)

/////////////////////////// ProcessTracker ////////////////////////////////

type stats struct {
	CountProcessCreated    int64
	CountNetConn           int64
	CountFilesCreated      int64
	CountFilesCreatedByExt map[string]*int64
}

type processTrack struct {
	Image                string
	ParentImage          string
	PID                  int64
	CommandLine          string
	ParentCommandLine    string
	CurrentDirectory     string
	ProcessGUID          string
	User                 string
	ParentUser           string
	IntegrityLevel       string
	ParentIntegrityLevel string
	ParentProcessGUID    string
	Services             string
	History              []string
	Stats                stats
	MemDumped            bool
	TimeTerminated       time.Time
}

type ProcessTracker struct {
	sync.RWMutex
	guids map[string]*processTrack
	pids  map[int64]*processTrack
	free  *datastructs.Fifo
}

func NewProcessTracker() *ProcessTracker {
	pt := &ProcessTracker{
		guids: make(map[string]*processTrack),
		pids:  make(map[int64]*processTrack),
		free:  &datastructs.Fifo{},
	}
	// startup the routine to free resources
	pt.freeRtn()
	return pt
}

func (pt *ProcessTracker) freeRtn() {
	go func() {
		for {
			for e := pt.free.Pop(); e != nil; e = pt.free.Pop() {
				t := e.Value.(*processTrack)
				now := time.Now()
				// delete the track only after some time because some
				// events come after process terminate events
				timeToDel := t.TimeTerminated.Add(time.Second * 10)
				if timeToDel.After(now) {
					delta := timeToDel.Sub(now)
					time.Sleep(delta)
				}
				pt.Del(t.ProcessGUID)
			}
			time.Sleep(1 * time.Second)
		}
	}()
}

func (pt *ProcessTracker) Add(t *processTrack) {
	pt.Lock()
	defer pt.Unlock()
	pt.guids[t.ProcessGUID] = t
	pt.pids[t.PID] = t
}

func (pt *ProcessTracker) GetByGuid(guid string) *processTrack {
	pt.RLock()
	defer pt.RUnlock()
	return pt.guids[guid]
}

func (pt *ProcessTracker) GetByPID(pid int64) *processTrack {
	pt.RLock()
	defer pt.RUnlock()
	return pt.pids[pid]
}

func (pt *ProcessTracker) ContainsGuid(guid string) bool {
	pt.RLock()
	defer pt.RUnlock()
	_, ok := pt.guids[guid]
	return ok
}

func (pt *ProcessTracker) ContainsPID(pid int64) bool {
	pt.RLock()
	defer pt.RUnlock()
	_, ok := pt.pids[pid]
	return ok
}

func (pt *ProcessTracker) Terminate(guid string) error {
	if t := pt.GetByGuid(guid); t != nil {
		t.TimeTerminated = time.Now()
		pt.free.Push(t)
	}
	return nil
}

func (pt *ProcessTracker) Del(guid string) {
	if t := pt.GetByGuid(guid); t != nil {
		pt.Lock()
		defer pt.Unlock()
		delete(pt.guids, guid)
		delete(pt.pids, t.PID)
	}
}

////////////////////////////////// Hooks //////////////////////////////////

var (
	// Globals needed by Hooks
	dumpDirectory    string
	selfGUID         string
	bootCompleted    bool
	flagProcTermEn   bool // set the flag to true if process termination is enabled
	flagDumpCompress bool

	selfPath, _ = filepath.Abs(os.Args[0])
	selfPid     = os.Getpid()

	cryptoLockerFilecreateLimit = int64(50)
	dumpTresh                   = 8
)

var (
	// Filters definitions
	// DNSFilter filters any Windows-DNS-Client log
	fltDNS = hooks.NewFilter([]int64{}, "Microsoft-Windows-DNS-Client/Operational")
	// SysmonNetConnFilter filters any Sysmon network connection
	fltAnySysmon       = hooks.NewFilter([]int64{}, "Microsoft-Windows-Sysmon/Operational")
	fltProcessCreate   = hooks.NewFilter([]int64{1}, "Microsoft-Windows-Sysmon/Operational")
	fltNetworkConnect  = hooks.NewFilter([]int64{3}, "Microsoft-Windows-Sysmon/Operational")
	fltProcTermination = hooks.NewFilter([]int64{5}, "Microsoft-Windows-Sysmon/Operational")
	fltImageLoad       = hooks.NewFilter([]int64{7}, "Microsoft-Windows-Sysmon/Operational")
	fltProcessAccess   = hooks.NewFilter([]int64{10}, "Microsoft-Windows-Sysmon/Operational")
	fltRegSetValue     = hooks.NewFilter([]int64{13}, "Microsoft-Windows-Sysmon/Operational")
	fltNetwork         = hooks.NewFilter([]int64{3, 22}, "Microsoft-Windows-Sysmon/Operational")
	fltImageSize       = hooks.NewFilter([]int64{1, 6, 7}, "Microsoft-Windows-Sysmon/Operational")
	fltStats           = hooks.NewFilter([]int64{1, 3, 11}, "Microsoft-Windows-Sysmon/Operational")
	fltDumpFile        = hooks.NewFilter([]int64{1, 2, 6, 11, 13, 15, 20}, "Microsoft-Windows-Sysmon/Operational")
)

var (
	// Path definitions
	////////////////////////// Getters ///////////////////////////
	// DNS-Client logs
	pathDNSQueryValue   = evtx.Path("/Event/EventData/QueryName")
	pathDNSQueryType    = evtx.Path("/Event/EventData/QueryType")
	pathDNSQueryResults = evtx.Path("/Event/EventData/QueryResults")

	// Sysmon related paths
	pathSysmonDestIP            = evtx.Path("/Event/EventData/DestinationIp")
	pathSysmonDestHostname      = evtx.Path("/Event/EventData/DestinationHostname")
	pathSysmonImage             = evtx.Path("/Event/EventData/Image")
	pathSysmonCommandLine       = evtx.Path("/Event/EventData/CommandLine")
	pathSysmonParentCommandLine = evtx.Path("/Event/EventData/ParentCommandLine")
	pathSysmonParentImage       = evtx.Path("/Event/EventData/ParentImage")
	pathSysmonImageLoaded       = evtx.Path("/Event/EventData/ImageLoaded")

	// EventID 8: CreateRemoteThread
	pathCRTSourceProcessGuid = evtx.Path("/Event/EventData/SourceProcessGuid")
	pathCRTTargetProcessGuid = evtx.Path("/Event/EventData/TargetProcessGuid")

	// EventID 10: ProcessAccess
	pathSysmonSourceProcessGUID = evtx.Path("/Event/EventData/SourceProcessGUID")
	pathSysmonTargetProcessGUID = evtx.Path("/Event/EventData/TargetProcessGUID")

	// EventID 12,13,14: Registry
	pathSysmonTargetObject = evtx.Path("/Event/EventData/TargetObject")

	pathSysmonProcessGUID       = evtx.Path("/Event/EventData/ProcessGuid")
	pathSysmonParentProcessGUID = evtx.Path("/Event/EventData/ParentProcessGuid")
	pathSysmonParentProcessId   = evtx.Path("/Event/EventData/ParentProcessId")
	pathSysmonProcessId         = evtx.Path("/Event/EventData/ProcessId")
	pathSysmonSourceProcessId   = evtx.Path("/Event/EventData/SourceProcessId")
	pathSysmonTargetFilename    = evtx.Path("/Event/EventData/TargetFilename")
	pathSysmonCurrentDirectory  = evtx.Path("/Event/EventData/CurrentDirectory")
	pathSysmonDetails           = evtx.Path("/Event/EventData/Details")
	pathSysmonDestination       = evtx.Path("/Event/EventData/Destination")
	pathSysmonSourceImage       = evtx.Path("/Event/EventData/SourceImage")
	pathSysmonTargetImage       = evtx.Path("/Event/EventData/TargetImage")
	pathSysmonUser              = evtx.Path("/Event/EventData/User")
	pathSysmonIntegrityLevel    = evtx.Path("/Event/EventData/IntegrityLevel")

	// Gene criticality path
	pathGeneCriticality = evtx.Path("/Event/GeneInfo/Criticality")

	///////////////////////// Setters //////////////////////////////////////
	pathAncestors            = evtx.Path("/Event/EventData/Ancestors")
	pathParentUser           = evtx.Path("/Event/EventData/ParentUser")
	pathParentIntegrityLevel = evtx.Path("/Event/EventData/ParentIntegrityLevel")

	// Use to store image sizes information by hook
	pathImSize       = evtx.Path("/Event/EventData/ImageSize")
	pathImLoadedSize = evtx.Path("/Event/EventData/ImageLoadedSize")

	// Use to store process information by hook
	pathParentIntegrity  = evtx.Path("/Event/EventData/ParentProcessIntegrity")
	pathProcessIntegrity = evtx.Path("/Event/EventData/ProcessIntegrity")
	pathIntegrityTimeout = evtx.Path("/Event/EventData/IntegrityTimeout")

	// Use to store pathServices information by hook
	pathServices       = evtx.Path("/Event/EventData/Services")
	pathSourceServices = evtx.Path("/Event/EventData/SourceServices")
	pathTargetServices = evtx.Path("/Event/EventData/TargetServices")

	// Use to store process by hook
	pathSourceIsParent = evtx.Path("/Event/EventData/SourceIsParent")

	// Use to store value size by hooking on SetValue events
	pathValueSize = evtx.Path("/Event/EventData/ValueSize")

	// Use to store parent image and command line in image load events
	pathImageLoadParentImage       = evtx.Path("/Event/EventData/ParentImage")
	pathImageLoadParentCommandLine = evtx.Path("/Event/EventData/ParentCommandLine")

	// Used to store user and integrity information in sysmon CreateRemoteThread and ProcessAccess events
	pathSourceUser              = evtx.Path("/Event/EventData/SourceUser")
	pathSourceIntegrityLevel    = evtx.Path("/Event/EventData/SourceIntegrityLevel")
	pathTargetUser              = evtx.Path("/Event/EventData/TargetUser")
	pathTargetIntegrityLevel    = evtx.Path("/Event/EventData/TargetIntegrityLevel")
	pathTargetParentProcessGuid = evtx.Path("/Event/EventData/TargetParentProcessGuid")
)

var (
	processTracker = NewProcessTracker()

	blacklistedImages = datastructs.NewSyncedSet()

	terminated = datastructs.NewSyncedSet()

	memdumped  = datastructs.NewSyncedSet()
	memdumping = datastructs.NewSyncedSet()

	fileDumped = datastructs.NewSyncedSet()

	parallelHooks = semaphore.New(4)

	compressionIsRunning = false
	compressionChannel   = make(chan string)
)

func toString(i interface{}) string {
	return fmt.Sprintf("%v", i)
}

// helper function which checks if the event belongs to current WHIDS
func isSelf(e *evtx.GoEvtxMap) bool {
	if pguid, err := e.GetString(&pathSysmonParentProcessGUID); err == nil {
		if pguid == selfGUID {
			return true
		}
	}
	if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		if guid == selfGUID {
			return true
		}
	}
	if sguid, err := e.GetString(&pathSysmonSourceProcessGUID); err == nil {
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
		path = &pathSysmonImage
		modpath = &pathImSize
	default:
		path = &pathSysmonImageLoaded
		modpath = &pathImLoadedSize
	}
	if image, err := e.GetString(path); err == nil {
		if fsutil.IsFile(image) {
			if stat, err := os.Stat(image); err == nil {
				e.Set(modpath, toString(stat.Size()))
			}
		}
	}
}

func hookImageLoad(e *evtx.GoEvtxMap) {
	e.Set(&pathImageLoadParentImage, "?")
	e.Set(&pathImageLoadParentCommandLine, "?")
	if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		if track := processTracker.GetByGuid(guid); track != nil {
			e.Set(&pathImageLoadParentImage, track.ParentImage)
			e.Set(&pathImageLoadParentCommandLine, track.ParentCommandLine)
		}
	}
}

// hook tracking processes
func hookTrack(e *evtx.GoEvtxMap) {
	// Default values
	e.Set(&pathAncestors, "?")
	e.Set(&pathParentUser, "?")
	e.Set(&pathParentIntegrityLevel, "?")
	// We need to be sure that process termination is enabled
	// before initiating process tracking not to fill up memory
	// with structures that will never be freed
	if flagProcTermEn || !bootCompleted {
		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
				if image, err := e.GetString(&pathSysmonImage); err == nil {
					// Boot sequence is completed when LogonUI.exe is strarted
					if strings.ToLower(image) == strings.ToLower("C:\\Windows\\System32\\LogonUI.exe") {
						log.Infof("Boot sequence completed")
						bootCompleted = true
					}
					if commandLine, err := e.GetString(&pathSysmonCommandLine); err == nil {
						if pCommandLine, err := e.GetString(&pathSysmonParentCommandLine); err == nil {
							if pImage, err := e.GetString(&pathSysmonParentImage); err == nil {
								if pguid, err := e.GetString(&pathSysmonParentProcessGUID); err == nil {
									if user, err := e.GetString(&pathSysmonUser); err == nil {
										if il, err := e.GetString(&pathSysmonIntegrityLevel); err == nil {
											if cd, err := e.GetString(&pathSysmonCurrentDirectory); err == nil {
												track := &processTrack{
													Image:             image,
													ParentImage:       pImage,
													CommandLine:       commandLine,
													ParentCommandLine: pCommandLine,
													CurrentDirectory:  cd,
													PID:               pid,
													User:              user,
													IntegrityLevel:    il,
													ProcessGUID:       guid,
													ParentProcessGUID: pguid,
													History:           make([]string, 0),
													Stats:             stats{0, 0, 0, make(map[string]*int64)},
												}
												if parent := processTracker.GetByGuid(pguid); parent != nil {
													track.History = append(parent.History, parent.Image)
													track.ParentUser = parent.User
													track.ParentIntegrityLevel = parent.IntegrityLevel
												} else {
													// For processes created by System
													if pimage, err := e.GetString(&pathSysmonParentImage); err == nil {
														track.History = append(track.History, pimage)
													}
												}
												processTracker.Add(track)
												e.Set(&pathAncestors, strings.Join(track.History, "|"))
												if track.ParentUser != "" {
													e.Set(&pathParentUser, track.ParentUser)
												}
												if track.ParentIntegrityLevel != "" {
													e.Set(&pathParentIntegrityLevel, track.ParentIntegrityLevel)
												}
											}
										}
									}
								}
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
		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			//v, ok := processTracker.Get(guid)
			//if ok {
			if pt := processTracker.GetByGuid(guid); pt != nil {
				//pt := v.(*processTrack)
				switch e.EventID() {
				case 1:
					pt.Stats.CountProcessCreated++
				case 3:
					pt.Stats.CountNetConn++
				case 11:
					if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
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
/*func hookCryptoProtect(e *evtx.GoEvtxMap) {
	if e.EventID() == 11 {
		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			v, ok := processTracker.Get(guid)
			if ok && !terminated.Contains(guid) {
				pt := v.(*processTrack)
				if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
					ext := filepath.Ext(target)
					cnt := pt.Stats.CountFilesCreatedByExt[ext]
					if cnt != nil && !isWhitelistedExt(ext) {
						if *cnt > cryptoLockerFilecreateLimit {
							if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
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
}*/

// hook terminating previously blacklisted processes (according to their CommandLine)
func hookTerminator(e *evtx.GoEvtxMap) {
	if e.EventID() == 1 {
		if commandLine, err := e.GetString(&pathSysmonCommandLine); err == nil {
			if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
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
	if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		// Releasing resources
		processTracker.Terminate(guid)
		terminated.Del(guid)
		memdumped.Del(guid)
		//svchostTrack.Del(guid)
	}
}

func hookSelfGUID(e *evtx.GoEvtxMap) {
	if selfGUID == "" {
		if e.EventID() == 1 {
			// Sometimes it happens that other events are generated before process creation
			// Check parent image first because we launch whids.exe -h to test process termination
			// and we catch it up if we check image first
			if pimage, err := e.GetString(&pathSysmonParentImage); err == nil {
				//log.Infof("pimage=%s self=%s", pimage, selfPath)
				if pimage == selfPath {
					if pguid, err := e.GetString(&pathSysmonParentProcessGUID); err == nil {
						selfGUID = pguid
						log.Infof("Found self GUID from PGUID: %s", selfGUID)
						return
					}
				}
			}
			if image, err := e.GetString(&pathSysmonImage); err == nil {
				//log.Infof("image=%s self=%s", image, selfPath)
				if image == selfPath {
					if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
						selfGUID = guid
						log.Infof("Found self GUID: %s", selfGUID)
						return
					}
				}
			}
		}
	}
}

func hookProcessIntegrity(e *evtx.GoEvtxMap) {
	// Sysmon Create Process
	if bootCompleted && e.EventID() == 1 {
		// Default values
		e.Set(&pathParentIntegrity, toString(-1.0))
		e.Set(&pathProcessIntegrity, toString(-1.0))
		e.Set(&pathIntegrityTimeout, toString(false))

		if ppid, err := e.GetInt(&pathSysmonParentProcessId); err == nil {
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
							e.Set(&pathParentIntegrity, toString(utils.Round(float64(bdiff)*100/float64(slen), 2)))
						}
					}
				}
			} else {
				log.Debugf("Cannot check integrity of parent PPID=%d: process terminated", ppid)
			}
		}

		if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
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
								e.Set(&pathIntegrityTimeout, toString(true))
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
										e.Set(&pathProcessIntegrity, toString(utils.Round(float64(bdiff)*100/float64(slen), 2)))
									}
								}
							}
						}
					}
				}
			} else {
				log.Debugf("Cannot check integrity of PID=%d: process terminated", pid)
			}
		}
	}
}

// too big to be put in hookEnrichAnySysmon
func hookEnrichServices(e *evtx.GoEvtxMap) {
	// We do this only if we can cleanup resources
	eventID := e.EventID()
	if flagProcTermEn {
		switch eventID {
		case 6, 19, 20, 21:
			// Nothing to do
			break
		case 8, 10:
			e.Set(&pathSourceServices, "?")
			e.Set(&pathTargetServices, "?")

			sguidPath := &pathSysmonSourceProcessGUID
			tguidPath := &pathSysmonTargetProcessGUID

			if eventID == 8 {
				sguidPath = &pathCRTSourceProcessGuid
				tguidPath = &pathCRTTargetProcessGuid
			}

			if sguid, err := e.GetString(sguidPath); err == nil {
				if t := processTracker.GetByGuid(sguid); t != nil {
					e.Set(&pathSourceServices, t.Services)
				}
			}

			if tguid, err := e.GetString(tguidPath); err == nil {
				if t := processTracker.GetByGuid(tguid); t != nil {
					e.Set(&pathTargetServices, t.Services)
				}
			}
		default:
			e.Set(&pathServices, "?")
			// image, guid and pid are supposed to be available for all the remaining Sysmon logs
			if image, err := e.GetString(&pathSysmonImage); err == nil {
				if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
					if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
						track := processTracker.GetByGuid(guid)
						// we missed process creation so we create a minimal track
						if track == nil {
							track = &processTrack{
								Image:       image,
								ProcessGUID: guid,
								PID:         pid,
								Stats:       stats{0, 0, 0, make(map[string]*int64)},
							}
							processTracker.Add(track)
						}

						if track.Services == "" {
							track.Services, err = advapi32.ServiceWin32NamesByPid(uint32(pid))
							if err != nil {
								log.Errorf("Failed to resolve service from PID=%d: %s", pid, err)
								track.Services = "Error"
							}
						}
						e.Set(&pathServices, track.Services)
					}
				}
			}
		}
	}
}

func hookProcessAccess(e *evtx.GoEvtxMap) {
	// Only ProcessAccess events
	if e.EventID() == 10 {
		e.Set(&pathSourceIsParent, "?")
		if sguid, err := e.GetString(&pathSysmonSourceProcessGUID); err == nil {
			if tguid, err := e.GetString(&pathSysmonTargetProcessGUID); err == nil {
				switch {
				case processTracker.ContainsGuid(tguid):
					if t := processTracker.GetByGuid(tguid); t != nil {
						// check if sguid is the same as the parent process
						if t.ParentProcessGUID == sguid {
							e.Set(&pathSourceIsParent, toString(true))
						} else {
							e.Set(&pathSourceIsParent, toString(false))
						}
					}
				case processTracker.ContainsGuid(sguid):
					// if we tracked the source process, we are supposed
					// to have tracked the target, if the target is a child
					// so it means that if we did not track the target and
					// we tracked the source the target is not a child of the source
					e.Set(&pathSourceIsParent, toString(false))
				}
			}
		}
	}
}

func hookSetValueSize(e *evtx.GoEvtxMap) {
	e.Set(&pathValueSize, toString(-1))
	if targetObject, err := e.GetString(&pathSysmonTargetObject); err == nil {
		size, err := advapi32.RegGetValueSizeFromString(targetObject)
		if err != nil {
			log.Errorf("Failed to get value size \"%s\": %s", targetObject, err)
		}
		e.Set(&pathValueSize, toString(size))
	}
}

/*func hookNetwork(e *evtx.GoEvtxMap) {
	// Default value
	e.Set(&pathSysmonCommandLine, "?")
	if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		if pt := processTracker.GetByGuid(guid); pt != nil {
			// We add the parent command line to the network connection
			e.Set(&pathSysmonCommandLine, pt.CommandLine)
		}
	}
}*/

func hookEnrichAnySysmon(e *evtx.GoEvtxMap) {
	eventID := e.EventID()
	switch eventID {
	case 1, 6:
		// ProcessCreation is already processed in hookTrack
		// DriverLoad does not contain any GUID information
		break

	case 8, 10:
		// Default Values for the fields
		e.Set(&pathSourceUser, "?")
		e.Set(&pathSourceIntegrityLevel, "?")
		e.Set(&pathTargetUser, "?")
		e.Set(&pathTargetIntegrityLevel, "?")
		e.Set(&pathTargetParentProcessGuid, "?")

		sguidPath := &pathSysmonSourceProcessGUID
		tguidPath := &pathSysmonTargetProcessGUID

		if eventID == 8 {
			sguidPath = &pathCRTSourceProcessGuid
			tguidPath = &pathCRTTargetProcessGuid
		}

		if sguid, err := e.GetString(sguidPath); err == nil {
			if tguid, err := e.GetString(tguidPath); err == nil {
				if strack := processTracker.GetByGuid(sguid); strack != nil {
					e.Set(&pathSourceUser, strack.User)
					e.Set(&pathSourceIntegrityLevel, strack.IntegrityLevel)
				}
				if ttrack := processTracker.GetByGuid(tguid); ttrack != nil {
					e.Set(&pathTargetUser, ttrack.User)
					e.Set(&pathTargetIntegrityLevel, ttrack.IntegrityLevel)
					e.Set(&pathTargetParentProcessGuid, ttrack.ParentProcessGUID)
				}
			}
		}
		break

	default:
		hasComLine := true

		// Default Values for the fields
		e.Set(&pathSysmonUser, "?")
		e.Set(&pathSysmonIntegrityLevel, "?")
		e.Set(&pathSysmonCurrentDirectory, "?")

		if _, err := e.GetString(&pathSysmonCommandLine); err != nil {
			e.Set(&pathSysmonCommandLine, "?")
			hasComLine = false
		}

		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			if track := processTracker.GetByGuid(guid); track != nil {
				// if event does not have command line
				if !hasComLine {
					e.Set(&pathSysmonCommandLine, track.CommandLine)
				}
				e.Set(&pathSysmonUser, track.User)
				e.Set(&pathSysmonIntegrityLevel, track.IntegrityLevel)
				e.Set(&pathSysmonCurrentDirectory, track.CurrentDirectory)
			}
		}
	}
}

//////////////////// Hooks' helpers /////////////////////

func getCriticality(e *evtx.GoEvtxMap) int {
	if c, err := e.Get(&pathGeneCriticality); err == nil {
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

func dumpPidAndCompress(pid int, guid, id string) {
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
	var err error
	os.MkdirAll(path, defaultPerms)
	sha256, err := file.Sha256(src)
	if err != nil {
		return err
	}
	// replace : in case we are dumping an ADS
	base := strings.Replace(filepath.Base(src), ":", "_ADS_", -1)
	dst := filepath.Join(path, fmt.Sprintf("%d_%s.bin", time.Now().Unix(), base))
	// dump sha256 of file anyway
	ioutil.WriteFile(fmt.Sprintf("%s.sha256", dst), []byte(sha256), 600)
	if !fileDumped.Contains(sha256) {
		log.Debugf("Dumping file: %s->%s", src, dst)
		if err = fsutil.CopyFile(src, dst); err == nil {
			compress(dst)
			fileDumped.Add(sha256)
		}
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
			pidPath = &pathSysmonSourceProcessId
			procGUIDPath = &pathSysmonSourceProcessGUID
		default:
			pidPath = &pathSysmonProcessId
			procGUIDPath = &pathSysmonProcessGUID
		}

		if guid, err := e.GetString(procGUIDPath); err == nil {
			if pid, err := e.GetInt(pidPath); err == nil {
				dumpEventAndCompress(e, guid)
				dumpPidAndCompress(int(pid), guid, idFromEvent(e))
			}
		}

	}()
}

// ToDo: test this function
func hookDumpRegistry(e *evtx.GoEvtxMap) {
	// we dump only if alert is relevant
	if getCriticality(e) < dumpTresh {
		return
	}

	parallelHooks.Acquire()
	go func() {
		defer parallelHooks.Release()
		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			if targetObject, err := e.GetString(&pathSysmonTargetObject); err == nil {
				if details, err := e.GetString(&pathSysmonDetails); err == nil {
					// We dump only if Details is "Binary Data" since the other kinds can be seen in the raw event
					if details == "Binary Data" {
						dumpPath := filepath.Join(dumpDirectory, guid, idFromEvent(e), "reg.txt")
						key, value := filepath.Split(targetObject)
						dumpEventAndCompress(e, guid)
						content, err := utils.RegQuery(key, value)
						if err != nil {
							log.Errorf("Failed to run reg query: %s", err)
							content = fmt.Sprintf("Error Dumping %s: %s", targetObject, err)
						}
						err = ioutil.WriteFile(dumpPath, []byte(content), 0600)
						if err != nil {
							log.Errorf("Failed to write registry content to file: %s", err)
							return
						}
						compress(dumpPath)
						return
					}
					return
				}
			}
		}
		log.Errorf("Failed to dump registry from event")
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
		guid := "{00000000-0000-0000-0000-000000000000}"
		tmpGUID, err := e.GetString(&pathSysmonProcessGUID)
		if err != nil {
			if tmpGUID, err = e.GetString(&pathSysmonSourceProcessGUID); err == nil {
				guid = tmpGUID
			}
		} else {
			guid = tmpGUID
		}

		dumpPath := filepath.Join(dumpDirectory, guid, idFromEvent(e))
		dumpEventAndCompress(e, guid)

		switch e.EventID() {

		case 2, 11, 15:
			if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
				if err = dumpFileAndCompress(target, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), target, err)
				}
			}

		case 6:
			if im, err := e.GetString(&pathSysmonImageLoaded); err == nil {
				if err = dumpFileAndCompress(im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}

		case 10:
			if sim, err := e.GetString(&pathSysmonSourceImage); err == nil {
				if err = dumpFileAndCompress(sim, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), sim, err)
				}
			}

		case 13, 20:
			// for event ID 13
			path := &pathSysmonDetails
			if e.EventID() == 20 {
				path = &pathSysmonDestination
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

		default:
			if cl, err := e.GetString(&pathSysmonCommandLine); err == nil {
				if cwd, err := e.GetString(&pathSysmonCurrentDirectory); err == nil {
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
			if im, err := e.GetString(&pathSysmonImage); err == nil {
				if err = dumpFileAndCompress(im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}
			if pim, err := e.GetString(&pathSysmonParentImage); err == nil {
				if err = dumpFileAndCompress(pim, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), pim, err)
				}
			}
		}
	}()
}
