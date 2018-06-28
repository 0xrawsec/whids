package main

import (
	"hooks"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
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
	sysmonProcessGUID       = evtx.Path("/Event/EventData/ProcessGuid")
	sysmonParentProcessGUID = evtx.Path("/Event/EventData/ParentProcessGuid")
	sysmonProcessId         = evtx.Path("/Event/EventData/ProcessId")
	sysmonTargetFilename    = evtx.Path("/Event/EventData/TargetFilename")

	imSizePath       = evtx.Path("/Event/EventData/ImageSize")
	imLoadedSizePath = evtx.Path("/Event/EventData/ImageLoadedSize")

	// map mapping ip to domains
	dnsResolution = make(map[string]string)

	// map of processStats key: GUID
	processTracker = make(map[string]*processTrack)

	blacklistedImages = datastructs.NewSyncedSet()

	terminated = datastructs.NewSyncedSet()
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
				e.Set(modpath, stat.Size())
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
// it also cleanup the processStatMap
func hookProcTerm(e *evtx.GoEvtxMap) {
	log.Debug("Process termination events are enabled")
	flagProcTermEn = true
	if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
		// We clean up data structures
		delete(processTracker, guid)
		terminated.Del(guid)
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
			if image, err := e.GetString(&sysmonImage); err == nil {
				if image == selfPath {
					if guid, err := e.GetString(&sysmonProcessGUID); err == nil {
						selfGUID = guid
						log.Debugf("Found self GUID: %s", selfGUID)
						return
					}
				}
			}
			// Sometimes it happens that other events are generated before process creation
			if pimage, err := e.GetString(&sysmonParentImage); err == nil {
				if pimage == selfPath {
					if pguid, err := e.GetString(&sysmonParentProcessGUID); err == nil {
						selfGUID = pguid
						log.Debugf("Found self GUID: %s", selfGUID)
						return
					}
				}
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////
