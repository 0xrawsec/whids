package hids

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/crypto/file"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/golang-win32/win32/dbghelp"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
)

////////////////////////////////// Hooks //////////////////////////////////

const (
	// Empty GUID
	nullGUID = "{00000000-0000-0000-0000-000000000000}"
)

const (
	// Actions
	ActionKill      = "kill"
	ActionBlacklist = "blacklist"
	ActionMemdump   = "memdump"
	ActionFiledump  = "filedump"
	ActionRegdump   = "regdump"
	ActionReport    = "report"
)

var (
	selfPath, _ = filepath.Abs(os.Args[0])
)

var (
	compressionChannel = make(chan string)

	errServiceResolution = fmt.Errorf("error resolving service name")
)

// hook applying on Sysmon events containing image information and
// adding a new field containing the image size
func hookSetImageSize(h *HIDS, e *event.EdrEvent) {
	var path engine.XPath
	var modpath engine.XPath
	switch e.EventID() {
	case SysmonProcessCreate:
		path = pathSysmonImage
		modpath = pathImSize
	default:
		path = pathSysmonImageLoaded
		modpath = pathImLoadedSize
	}
	if image, ok := e.GetString(path); ok {
		if fsutil.IsFile(image) {
			if stat, err := os.Stat(image); err == nil {
				e.Set(modpath, toString(stat.Size()))
			}
		}
	}
}

func hookImageLoad(h *HIDS, e *event.EdrEvent) {
	e.Set(pathImageLoadParentImage, "?")
	e.Set(pathImageLoadParentCommandLine, "?")
	if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
		if track := h.processTracker.GetByGuid(guid); track != nil {
			// we get a module info from cache or we update
			i := h.processTracker.GetModuleOrUpdate(ModuleInfoFromEvent(e))

			// make sure that we are taking signature of the image and not
			// one of its DLL
			if i.Image == track.Image {
				track.Signed = i.Signed
				track.Signature = i.Signature
				track.SignatureStatus = i.SignatureStatus
			} else {
				// update module list
				track.Modules = append(track.Modules, i)
			}

			e.Set(pathImageLoadParentImage, track.ParentImage)
			e.Set(pathImageLoadParentCommandLine, track.ParentCommandLine)
		}
	}
}

// hooks Windows DNS client logs and maintain a domain name resolution table
/*func hookDNS(h *HIDS, e *event.EdrEvent) {
	if qresults, err := e.GetString(pathQueryResults); err == nil {
		if qresults != "" && qresults != "-" {
			records := strings.Split(qresults, ";")
			for _, r := range records {
				// check if it is a valid IP
				if net.ParseIP(r) != nil {
					if qvalue, err := e.GetString(pathQueryName); err == nil {
						dnsResolution[r] = qvalue
					}
				}
			}
		}
	}
}*/

// hook tracking processes
func hookTrack(h *HIDS, e *event.EdrEvent) {
	switch e.EventID() {
	case SysmonProcessCreate:
		// Default values
		e.Set(pathAncestors, "?")
		e.Set(pathParentUser, "?")
		e.Set(pathParentIntegrityLevel, "?")
		e.Set(pathParentServices, "?")
		// We need to be sure that process termination is enabled
		// before initiating process tracking not to fill up memory
		// with structures that will never be freed
		if h.flagProcTermEn || !h.bootCompleted {
			if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
				if pid, ok := e.GetInt(pathSysmonProcessId); ok {
					if image, ok := e.GetString(pathSysmonImage); ok {
						// Boot sequence is completed when LogonUI.exe is strarted
						if strings.EqualFold(image, "C:\\Windows\\System32\\LogonUI.exe") {
							log.Infof("Boot sequence completed")
							h.bootCompleted = true
						}
						if commandLine, ok := e.GetString(pathSysmonCommandLine); ok {
							if pCommandLine, ok := e.GetString(pathSysmonParentCommandLine); ok {
								if pImage, ok := e.GetString(pathSysmonParentImage); ok {
									if pguid, ok := e.GetString(pathSysmonParentProcessGUID); ok {
										if user, ok := e.GetString(pathSysmonUser); ok {
											if il, ok := e.GetString(pathSysmonIntegrityLevel); ok {
												if cd, ok := e.GetString(pathSysmonCurrentDirectory); ok {
													if hashes, ok := e.GetString(pathSysmonHashes); ok {

														track := NewProcessTrack(image, pguid, guid, pid)
														track.ParentImage = pImage
														track.CommandLine = commandLine
														track.ParentCommandLine = pCommandLine
														track.CurrentDirectory = cd
														track.User = user
														track.IntegrityLevel = il
														track.SetHashes(hashes)

														if parent := h.processTracker.GetByGuid(pguid); parent != nil {
															track.Ancestors = append(parent.Ancestors, parent.Image)
															track.ParentUser = parent.User
															track.ParentIntegrityLevel = parent.IntegrityLevel
															track.ParentServices = parent.Services
															track.ParentCurrentDirectory = parent.CurrentDirectory
														} else {
															// For processes created by System
															if pimage, ok := e.GetString(pathSysmonParentImage); ok {
																track.Ancestors = append(track.Ancestors, pimage)
															}
														}
														h.processTracker.Add(track)
														e.Set(pathAncestors, strings.Join(track.Ancestors, "|"))
														if track.ParentUser != "" {
															e.Set(pathParentUser, track.ParentUser)
														}
														if track.ParentIntegrityLevel != "" {
															e.Set(pathParentIntegrityLevel, track.ParentIntegrityLevel)
														}
														if track.ParentServices != "" {
															e.Set(pathParentServices, track.ParentServices)
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
	case SysmonDriverLoad:
		d := DriverInfoFromEvent(e)
		h.processTracker.Drivers = append(h.processTracker.Drivers, *d)
	}
}

// hook managing statistics about some events
func hookStats(h *HIDS, e *event.EdrEvent) {
	// We do not store stats if process termination is not enabled
	if h.flagProcTermEn {
		if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
			if pt := h.processTracker.GetByGuid(guid); pt != nil {
				switch e.EventID() {
				case SysmonProcessCreate:
					pt.Stats.CreateProcessCount++

				case SysmonNetworkConnect:
					if ip, ok := e.GetString(pathSysmonDestIP); ok {
						if port, ok := e.GetInt(pathSysmonDestPort); ok {
							if ts, ok := e.GetString(pathSysmonUtcTime); ok {
								pt.Stats.UpdateCon(ts, ip, uint16(port))
							}
						}
					}
				case SysmonDNSQuery:
					if ts, ok := e.GetString(pathSysmonUtcTime); ok {
						if qvalue, ok := e.GetString(pathQueryName); ok {
							if qresults, ok := e.GetString(pathQueryResults); ok {
								if qresults != "" && qresults != "-" {
									records := strings.Split(qresults, ";")
									for _, r := range records {
										// check if it is a valid IP
										if net.ParseIP(r) != nil {
											pt.Stats.UpdateNetResolve(ts, r, qvalue)
										}
									}
								}
							}
						}
					}
				case SysmonFileCreate:
					now := time.Now()

					// Set new fields
					e.Set(pathFileCount, "?")
					e.Set(pathFileCountByExt, "?")
					e.Set(pathFileExtension, "?")

					if pt.Stats.Files.TimeFirstFileCreated.IsZero() {
						pt.Stats.Files.TimeFirstFileCreated = now
					}

					if target, ok := e.GetString(pathSysmonTargetFilename); ok {
						ext := filepath.Ext(target)
						pt.Stats.Files.CountFilesCreatedByExt[ext]++
						// Setting file count by extension
						e.Set(pathFileCountByExt, toString(pt.Stats.Files.CountFilesCreatedByExt[ext]))
						// Setting file extension
						e.Set(pathFileExtension, ext)
					}
					pt.Stats.Files.CountFilesCreated++
					// Setting total file count
					e.Set(pathFileCount, toString(pt.Stats.Files.CountFilesCreated))
					// Setting frequency
					freq := now.Sub(pt.Stats.Files.TimeFirstFileCreated)
					if freq != 0 {
						eps := pt.Stats.Files.CountFilesCreated * int64(math.Pow10(9)) / freq.Nanoseconds()
						e.Set(pathFileFrequency, toString(int64(eps)))
					} else {
						e.Set(pathFileFrequency, toString(0))
					}
					// Finally set last event timestamp
					pt.Stats.Files.TimeLastFileCreated = now

				case SysmonFileDelete, SysmonFileDeleteDetected:
					now := time.Now()

					// Set new fields
					e.Set(pathFileCount, "?")
					e.Set(pathFileCountByExt, "?")
					e.Set(pathFileExtension, "?")

					if pt.Stats.Files.TimeFirstFileDeleted.IsZero() {
						pt.Stats.Files.TimeFirstFileDeleted = now
					}

					if target, ok := e.GetString(pathSysmonTargetFilename); ok {
						ext := filepath.Ext(target)
						pt.Stats.Files.CountFilesDeletedByExt[ext]++
						// Setting file count by extension
						e.Set(pathFileCountByExt, toString(pt.Stats.Files.CountFilesDeletedByExt[ext]))
						// Setting file extension
						e.Set(pathFileExtension, ext)
					}
					pt.Stats.Files.CountFilesDeleted++
					// Setting total file count
					e.Set(pathFileCount, toString(pt.Stats.Files.CountFilesDeleted))

					// Setting frequency
					freq := now.Sub(pt.Stats.Files.TimeFirstFileDeleted)
					if freq != 0 {
						eps := pt.Stats.Files.CountFilesDeleted * int64(math.Pow10(9)) / freq.Nanoseconds()
						e.Set(pathFileFrequency, toString(int64(eps)))
					} else {
						e.Set(pathFileFrequency, toString(0))
					}

					// Finally set last event timestamp
					pt.Stats.Files.TimeLastFileDeleted = time.Now()
				}
			}
		}
	}
}

func hookUpdateGeneScore(h *HIDS, e *event.EdrEvent) {
	if h.IsHIDSEvent(e) {
		return
	}

	if t := processTrackFromEvent(h, e); t != nil {
		if d := e.GetDetection(); d != nil {
			t.ThreatScore.Update(d)
		}
	}
}

func hookHandleActions(h *HIDS, e *event.EdrEvent) {
	var kill, memdump bool

	// We have to check that if we are handling one of
	// our event and we don't want to kill ourself
	if h.IsHIDSEvent(e) {
		return
	}

	// the only requirement to be able to handle action
	// is to have a process guuid
	if uuid := srcGUIDFromEvent(e); uuid != nullGUID {

		//if i, err := e.Get(&engine.ActionsPath); err == nil {
		if d := e.GetDetection(); d != nil {
			for _, i := range d.Actions.Slice() {
				action := i.(string)
				switch action {
				case ActionKill:
					kill = true
					if pt := processTrackFromEvent(h, e); pt != nil {
						// additional check not to suspend agent
						if pt.PID != int64(os.Getpid()) {
							// before we kill we suspend the process
							kernel32.SuspendProcess(int(pt.PID))
						}
					}
				case ActionBlacklist:
					if pt := processTrackFromEvent(h, e); pt != nil {
						// additional check not to blacklist agent
						if int(pt.PID) != os.Getpid() {
							h.processTracker.Blacklist(pt.CommandLine)
						}
					}
				case ActionMemdump:
					memdump = true
					dumpProcessRtn(h, e)
				case ActionRegdump:
					dumpRegistryRtn(h, e)
				case ActionFiledump:
					dumpFilesRtn(h, e)
				case ActionReport:
					dumpReportRtn(h, e)
				default:
					log.Errorf("Cannot handle %s action as it is unknown", action)
				}
			}

			// handle kill operation after the other actions
			if kill {
				if pt := processTrackFromEvent(h, e); pt != nil {
					if pt.PID != int64(os.Getpid()) {
						if memdump {
							// Wait we finish dumping before killing the process
							go func() {
								guid := pt.ProcessGUID
								for i := 0; i < 60 && !h.memdumped.Contains(guid); i++ {
									time.Sleep(1 * time.Second)
								}
								if err := pt.TerminateProcess(); err != nil {
									log.Errorf("Failed to terminate process PID=%d GUID=%s", pt.PID, pt.ProcessGUID)
								}
							}()
						} else if err := pt.TerminateProcess(); err != nil {
							log.Errorf("Failed to terminate process PID=%d GUID=%s", pt.PID, pt.ProcessGUID)
						}
					}
				}
			}
		}
	} else {
		log.Errorf("Failed to handle actions for event (channel: %s, id: %d): no process GUID available", e.Channel(), e.EventID())
	}
}

// hook terminating previously blacklisted processes (according to their CommandLine)
func hookTerminator(h *HIDS, e *event.EdrEvent) {
	if e.EventID() == SysmonProcessCreate {
		if commandLine, ok := e.GetString(pathSysmonCommandLine); ok {
			if pid, ok := e.GetInt(pathSysmonProcessId); ok {
				if h.processTracker.IsBlacklisted(commandLine) {
					log.Warnf("Terminating blacklisted  process PID=%d CommandLine=\"%s\"", pid, commandLine)
					if err := terminate(int(pid)); err != nil {
						log.Errorf("Failed to terminate process PID=%d: %s", pid, err)
					}
				}
			}
		}
	}
}

// hook setting flagProcTermEn variable
// it is also used to cleanup any structures needing to be cleaned
func hookProcTerm(h *HIDS, e *event.EdrEvent) {
	log.Debug("Process termination events are enabled")
	h.flagProcTermEn = true
	if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
		// Releasing resources
		h.processTracker.Terminate(guid)
		h.memdumped.Del(guid)
	}
}

func hookSelfGUID(h *HIDS, e *event.EdrEvent) {
	if h.guid == "" {
		if e.EventID() == SysmonProcessCreate {
			// Sometimes it happens that other events are generated before process creation
			// Check parent image first because we launch whids.exe -h to test process termination
			// and we catch it up if we check image first
			if pimage, ok := e.GetString(pathSysmonParentImage); ok {
				if pimage == selfPath {
					if pguid, ok := e.GetString(pathSysmonParentProcessGUID); ok {
						h.guid = pguid
						log.Infof("Found self GUID from PGUID: %s", h.guid)
						return
					}
				}
			}
			if image, ok := e.GetString(pathSysmonImage); ok {
				if image == selfPath {
					if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
						h.guid = guid
						log.Infof("Found self GUID: %s", h.guid)
						return
					}
				}
			}
		}
	}
}

func hookFileSystemAudit(h *HIDS, e *event.EdrEvent) {
	e.Set(pathSysmonCommandLine, "?")
	e.Set(pathSysmonProcessGUID, nullGUID)
	e.Set(pathImageHashes, "?")
	if pid, ok := e.GetInt(pathFSAuditProcessId); ok {
		if pt := h.processTracker.GetByPID(pid); pt != nil {
			if pt.CommandLine != "" {
				e.Set(pathSysmonCommandLine, pt.CommandLine)
			}
			if pt.hashes != "" {
				e.Set(pathImageHashes, pt.hashes)
			}
			if pt.ProcessGUID != "" {
				e.Set(pathSysmonProcessGUID, pt.ProcessGUID)
			}

			if obj, ok := e.GetString(pathFSAuditObjectName); ok {
				if fsutil.IsFile(obj) {
					pt.Stats.Files.LastAccessed.Add(obj)
				}
			}
		}
	}
}

func hookProcessIntegrityProcTamp(h *HIDS, e *event.EdrEvent) {
	// Default values
	e.Set(pathProcessIntegrity, toString(-1.0))

	// Sysmon Create Process
	if e.EventID() == SysmonProcessTampering {
		if pid, ok := e.GetInt(pathSysmonProcessId); ok {
			// prevent stopping our own process, it may happen in some
			// cases when selfGuid is not found fast enough
			if pid != int64(os.Getpid()) {
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
											integrity := utils.Round(float64(bdiff)*100/float64(slen), 2)
											e.Set(pathProcessIntegrity, toString(integrity))
										}
									}
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

// too big to be put in hookEnrichAnySysmon
func hookEnrichServices(h *HIDS, e *event.EdrEvent) {
	var err error

	// We do this only if we can cleanup resources
	eventID := e.EventID()
	if h.flagProcTermEn {
		switch eventID {
		case SysmonDriverLoad, SysmonWMIBinding, SysmonWMIConsumer, SysmonWMIFilter:
			// Nothing to do
			break
		case SysmonCreateRemoteThread, SysmonAccessProcess:
			e.Set(pathSourceServices, "?")
			e.Set(pathTargetServices, "?")

			sguidPath := pathSysmonSourceProcessGUID
			tguidPath := pathSysmonTargetProcessGUID

			if eventID == 8 {
				sguidPath = pathSysmonCRTSourceProcessGuid
				tguidPath = pathSysmonCRTTargetProcessGuid
			}

			if sguid, ok := e.GetString(sguidPath); ok {
				// First try to resolve it by tracked process
				if t := h.processTracker.GetByGuid(sguid); t != nil {
					e.Set(pathSourceServices, t.Services)
				} else {
					// If it fails we resolve the services by PID
					if spid, ok := e.GetInt(pathSysmonSourceProcessId); ok {
						if svcs, err := advapi32.ServiceWin32NamesByPid(uint32(spid)); err == nil {
							e.Set(pathSourceServices, svcs)
						} else {
							log.Errorf("Failed to resolve service from PID=%d: %s", spid, err)
							e.Set(pathSourceServices, errServiceResolution.Error())
						}
					}
				}
			}

			// First try to resolve it by tracked process
			if tguid, ok := e.GetString(tguidPath); ok {
				if t := h.processTracker.GetByGuid(tguid); t != nil {
					e.Set(pathTargetServices, t.Services)
				} else {
					// If it fails we resolve the services by PID
					if tpid, ok := e.GetInt(pathSysmonTargetProcessId); ok {
						if svcs, err := advapi32.ServiceWin32NamesByPid(uint32(tpid)); err == nil {
							e.Set(pathTargetServices, svcs)
						} else {
							log.Errorf("Failed to resolve service from PID=%d: %s", tpid, err)
							e.Set(pathTargetServices, errServiceResolution)
						}
					}
				}
			}
		default:
			e.Set(pathServices, "?")
			// image, guid and pid are supposed to be available for all the remaining Sysmon logs
			if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
				if pid, ok := e.GetInt(pathSysmonProcessId); ok {
					if track := h.processTracker.GetByGuid(guid); track != nil {
						if track.Services == "" {
							track.Services, err = advapi32.ServiceWin32NamesByPid(uint32(pid))
							if err != nil {
								log.Errorf("Failed to resolve service from PID=%d: %s", pid, ok)
								track.Services = errServiceResolution.Error()
							}
						}
						e.Set(pathServices, track.Services)
					} else {
						services, err := advapi32.ServiceWin32NamesByPid(uint32(pid))
						if err != nil {
							log.Errorf("Failed to resolve service from PID=%d: %s", pid, err)
							services = errServiceResolution.Error()
						}
						e.Set(pathServices, services)
					}
				}
			}
		}
	}
}

func hookSetValueSize(h *HIDS, e *event.EdrEvent) {
	e.Set(pathValueSize, toString(-1))
	if targetObject, ok := e.GetString(pathSysmonTargetObject); ok {
		size, err := advapi32.RegGetValueSizeFromString(targetObject)
		if err != nil {
			log.Errorf("Failed to get value size \"%s\": %s", targetObject, err)
		}
		e.Set(pathValueSize, toString(size))
	}
}

// hook that replaces the destination hostname of Sysmon Network connection
// event with the one previously found in the DNS logs
/*func hookEnrichDNSSysmon(h *HIDS, e *event.EdrEvent) {
	if ip, err := e.GetString(pathSysmonDestIP); err == nil {
		if dom, ok := dnsResolution[ip]; ok {
			e.Set(pathSysmonDestHostname, dom)
		}
	}
}*/

func hookEnrichAnySysmon(h *HIDS, e *event.EdrEvent) {
	eventID := e.EventID()
	switch eventID {
	case SysmonProcessCreate, SysmonDriverLoad:
		// ProcessCreation is already processed in hookTrack
		// DriverLoad does not contain any GUID information
		break

	case SysmonCreateRemoteThread, SysmonAccessProcess:
		// Handling CreateRemoteThread and ProcessAccess events
		// Default Values for the fields
		e.Set(pathSourceUser, "?")
		e.Set(pathSourceIntegrityLevel, "?")
		e.Set(pathTargetUser, "?")
		e.Set(pathTargetIntegrityLevel, "?")
		e.Set(pathTargetParentProcessGuid, "?")
		e.Set(pathSourceHashes, "?")
		e.Set(pathTargetHashes, "?")
		e.Set(pathSrcProcessGeneScore, "-1")
		e.Set(pathTgtProcessGeneScore, "-1")

		sguidPath := pathSysmonSourceProcessGUID
		tguidPath := pathSysmonTargetProcessGUID

		if eventID == SysmonCreateRemoteThread {
			sguidPath = pathSysmonCRTSourceProcessGuid
			tguidPath = pathSysmonCRTTargetProcessGuid
		}
		if sguid, ok := e.GetString(sguidPath); ok {
			if tguid, ok := e.GetString(tguidPath); ok {
				if strack := h.processTracker.GetByGuid(sguid); strack != nil {
					if strack.User != "" {
						e.Set(pathSourceUser, strack.User)
					}
					if strack.IntegrityLevel != "" {
						e.Set(pathSourceIntegrityLevel, strack.IntegrityLevel)
					}
					if strack.hashes != "" {
						e.Set(pathSourceHashes, strack.hashes)
					}
					// Source process score
					e.Set(pathSrcProcessGeneScore, toString(strack.ThreatScore.Score))
				}
				if ttrack := h.processTracker.GetByGuid(tguid); ttrack != nil {
					if ttrack.User != "" {
						e.Set(pathTargetUser, ttrack.User)
					}
					if ttrack.IntegrityLevel != "" {
						e.Set(pathTargetIntegrityLevel, ttrack.IntegrityLevel)
					}
					if ttrack.ParentProcessGUID != "" {
						e.Set(pathTargetParentProcessGuid, ttrack.ParentProcessGUID)
					}
					if ttrack.hashes != "" {
						e.Set(pathTargetHashes, ttrack.hashes)
					}
					// Target process score
					e.Set(pathTgtProcessGeneScore, toString(ttrack.ThreatScore.Score))
				}
			}
		}

	default:

		if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
			// Default value
			e.Set(pathProcessGeneScore, "-1")

			if track := h.processTracker.GetByGuid(guid); track != nil {
				// if event does not have CommandLine field
				if !eventHas(e, pathSysmonCommandLine) {
					e.Set(pathSysmonCommandLine, "?")
					if track.CommandLine != "" {
						e.Set(pathSysmonCommandLine, track.CommandLine)
					}
				}

				// if event does not have User field
				if !eventHas(e, pathSysmonUser) {
					e.Set(pathSysmonUser, "?")
					if track.User != "" {
						e.Set(pathSysmonUser, track.User)
					}
				}

				// if event does not have IntegrityLevel field
				if !eventHas(e, pathSysmonIntegrityLevel) {
					e.Set(pathSysmonIntegrityLevel, "?")
					if track.IntegrityLevel != "" {
						e.Set(pathSysmonIntegrityLevel, track.IntegrityLevel)
					}
				}

				// if event does not have CurrentDirectory field
				if !eventHas(e, pathSysmonCurrentDirectory) {
					e.Set(pathSysmonCurrentDirectory, "?")
					if track.CurrentDirectory != "" {
						e.Set(pathSysmonCurrentDirectory, track.CurrentDirectory)
					}
				}

				// event never has ImageHashes field since it is not Sysmon standard
				e.Set(pathImageHashes, "?")
				if track.hashes != "" {
					e.Set(pathImageHashes, track.hashes)
				}

				// Signature information
				e.Set(pathImageSigned, toString(track.Signed))
				e.Set(pathImageSignature, track.Signature)
				e.Set(pathImageSignatureStatus, track.SignatureStatus)

				// Overal criticality score
				e.Set(pathProcessGeneScore, toString(track.ThreatScore.Score))
			}
		}
	}
}

func hookClipboardEvents(h *HIDS, e *event.EdrEvent) {
	e.Set(pathSysmonClipboardData, "?")
	if hashes, ok := e.GetString(pathSysmonHashes); ok {
		fname := fmt.Sprintf("CLIP-%s", sysmonArcFileRe.ReplaceAllString(hashes, ""))
		path := filepath.Join(h.config.Sysmon.ArchiveDirectory, fname)
		if fi, err := os.Stat(path); err == nil {
			// limit size of ClipboardData to 1 Mega
			if fi.Mode().IsRegular() && fi.Size() < utils.Mega {
				if data, err := ioutil.ReadFile(path); err == nil {
					// We try to decode utf16 content because regexp can only match utf8
					// Thus doing this is needed to apply detection rule on clipboard content
					if enc, err := utils.Utf16ToUtf8(data); err == nil {
						e.Set(pathSysmonClipboardData, string(enc))
					} else {
						e.Set(pathSysmonClipboardData, fmt.Sprintf("%q", data))
					}
				}
			}
		}
	}
}

//////////////////// Hooks' helpers /////////////////////

func dumpPidAndCompress(h *HIDS, pid int, guid, id string) {
	// prevent stopping ourself (><)
	if kernel32.IsPIDRunning(pid) && pid != os.Getpid() && !h.memdumped.Contains(guid) && !h.dumping.Contains(guid) {

		// To avoid dumping the same process twice, possible if two alerts
		// comes from the same GUID in a short period of time
		h.dumping.Add(guid)
		defer h.dumping.Del(guid)

		tmpDumpDir := filepath.Join(h.config.Dump.Dir, guid, id)
		os.MkdirAll(tmpDumpDir, utils.DefaultPerms)
		module, err := kernel32.GetModuleFilenameFromPID(int(pid))
		if err != nil {
			log.Errorf("Cannot get module filename for memory dump PID=%d: %s", pid, err)
		}
		dumpFilename := fmt.Sprintf("%s_%d_%d.dmp", filepath.Base(module), pid, time.Now().UnixNano())
		dumpPath := filepath.Join(tmpDumpDir, dumpFilename)
		log.Infof("Trying to dump memory of process PID=%d Image=\"%s\"", pid, module)
		//log.Infof("Mock dump: %s", dumpFilename)
		err = dbghelp.FullMemoryMiniDump(pid, dumpPath)
		if err != nil {
			log.Errorf("Failed to dump process PID=%d Image=%s: %s", pid, module, err)
		} else {
			// dump was successfull
			h.memdumped.Add(guid)
			h.compress(dumpPath)
		}
	} else {
		log.Warnf("Cannot dump process PID=%d, the process is already terminated", pid)
	}

}

func dumpFileAndCompress(h *HIDS, src, path string) error {
	var err error
	os.MkdirAll(path, utils.DefaultPerms)
	sha256, err := file.Sha256(src)
	if err != nil {
		return err
	}
	// replace : in case we are dumping an ADS
	base := strings.Replace(filepath.Base(src), ":", "_ADS_", -1)
	dst := filepath.Join(path, fmt.Sprintf("%d_%s.bin", time.Now().UnixNano(), base))
	// dump sha256 of file anyway
	ioutil.WriteFile(fmt.Sprintf("%s.sha256", dst), []byte(sha256), 0600)
	if !h.filedumped.Contains(sha256) {
		log.Debugf("Dumping file: %s->%s", src, dst)
		if err = fsutil.CopyFile(src, dst); err == nil {
			h.compress(dst)
			h.filedumped.Add(sha256)
		}
	}
	return err
}

func dumpEventAndCompress(h *HIDS, e *event.EdrEvent, guid string) (err error) {
	dumpPath := dumpPrepareDumpFilename(e, h.config.Dump.Dir, guid, "event.json")

	if !h.dumping.Contains(dumpPath) && !h.filedumped.Contains(dumpPath) {
		h.dumping.Add(dumpPath)
		defer h.dumping.Del(dumpPath)

		var f *os.File

		f, err = os.Create(dumpPath)
		if err != nil {
			return
		}
		f.Write(utils.Json(e))
		f.Close()
		h.compress(dumpPath)
		h.filedumped.Add(dumpPath)
	}
	return
}

//////////////////// Post Detection Hooks /////////////////////

// variables specific to post-detection hooks
var (
	sysmonArcFileRe = regexp.MustCompile("(((SHA1|MD5|SHA256|IMPHASH)=)|,)")
)

func dumpPrepareDumpFilename(e *event.EdrEvent, dir, guid, filename string) string {
	id := e.Hash()
	tmpDumpDir := filepath.Join(dir, guid, id)
	os.MkdirAll(tmpDumpDir, utils.DefaultPerms)
	return filepath.Join(tmpDumpDir, filename)
}

func hookDumpProcess(h *HIDS, e *event.EdrEvent) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if h.IsHIDSEvent(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < h.config.Dump.Treshold {
		return
	}

	// if memory got already dumped
	if hasAction(e, ActionMemdump) {
		return
	}

	dumpProcessRtn(h, e)
}

// this hook can run async
func dumpProcessRtn(h *HIDS, e *event.EdrEvent) {
	// make it non blocking
	go func() {
		h.hookSemaphore.Acquire()
		defer h.hookSemaphore.Release()
		var guid string

		// it would be theoretically possible to dump a process
		// only from a PID (with a null GUID) but dumpPidAndCompress
		// is not designed for it.
		if guid = srcGUIDFromEvent(e); guid != nullGUID {
			// check if we should go on
			if !h.processTracker.CheckDumpCountOrInc(guid, h.config.Dump.MaxDumps, h.config.Dump.DumpUntracked) {
				log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
				return
			}

			if pt := h.processTracker.GetByGuid(guid); pt != nil {
				// if the process track is not nil we are sure PID is set
				dumpPidAndCompress(h, int(pt.PID), guid, e.Hash())
			}
		}
		dumpEventAndCompress(h, e, guid)
	}()
}

func hookDumpRegistry(h *HIDS, e *event.EdrEvent) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if h.IsHIDSEvent(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < h.config.Dump.Treshold {
		return
	}

	// if registry got already dumped
	if hasAction(e, ActionRegdump) {
		return
	}

	dumpRegistryRtn(h, e)
}

func dumpRegistryRtn(h *HIDS, e *event.EdrEvent) {
	// make it non blocking
	go func() {
		h.hookSemaphore.Acquire()
		defer h.hookSemaphore.Release()
		if guid, ok := e.GetString(pathSysmonProcessGUID); ok {

			// check if we should go on
			if !h.processTracker.CheckDumpCountOrInc(guid, h.config.Dump.MaxDumps, h.config.Dump.DumpUntracked) {
				log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
				return
			}

			if targetObject, ok := e.GetString(pathSysmonTargetObject); ok {
				if details, ok := e.GetString(pathSysmonDetails); ok {
					// We dump only if Details is "Binary Data" since the other kinds can be seen in the raw event
					if details == "Binary Data" {
						dumpPath := filepath.Join(h.config.Dump.Dir, guid, e.Hash(), "reg.txt")
						key, value := filepath.Split(targetObject)
						dumpEventAndCompress(h, e, guid)
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
						h.compress(dumpPath)
						return
					}
					return
				}
			}
		}
		log.Errorf("Failed to dump registry from event")
	}()
}

func dumpCommandLine(h *HIDS, e *event.EdrEvent, dumpPath string) {
	if cl, ok := e.GetString(pathSysmonCommandLine); ok {
		if cwd, ok := e.GetString(pathSysmonCurrentDirectory); ok {
			if argv, err := utils.ArgvFromCommandLine(cl); err == nil {
				if len(argv) > 1 {
					for _, arg := range argv[1:] {
						if fsutil.IsFile(arg) && !utils.IsPipePath(arg) {
							if err = dumpFileAndCompress(h, arg, dumpPath); err != nil {
								log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), arg, err)
							}
						}
						// try to dump a path relative to CWD
						relarg := filepath.Join(cwd, arg)
						if fsutil.IsFile(relarg) && !utils.IsPipePath(relarg) {
							if err = dumpFileAndCompress(h, relarg, dumpPath); err != nil {
								log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), relarg, err)
							}
						}
					}
				}
			}
		}
	}
}

func dumpParentCommandLine(h *HIDS, e *event.EdrEvent, dumpPath string) {
	if guid, ok := e.GetString(pathSysmonProcessGUID); ok {
		if track := h.processTracker.GetByGuid(guid); track != nil {
			if argv, err := utils.ArgvFromCommandLine(track.ParentCommandLine); err == nil {
				if len(argv) > 1 {
					for _, arg := range argv[1:] {
						if fsutil.IsFile(arg) && !utils.IsPipePath(arg) {
							if err = dumpFileAndCompress(h, arg, dumpPath); err != nil {
								log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), arg, err)
							}
						}
						// try to dump a path relative to parent CWD
						if track.ParentCurrentDirectory != "" {
							relarg := filepath.Join(track.ParentCurrentDirectory, arg)
							if fsutil.IsFile(relarg) && !utils.IsPipePath(relarg) {
								if err = dumpFileAndCompress(h, relarg, dumpPath); err != nil {
									log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), relarg, err)
								}
							}
						}
					}
				}
			}
		}
	}
}

func hookDumpFiles(h *HIDS, e *event.EdrEvent) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if h.IsHIDSEvent(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < h.config.Dump.Treshold {
		return
	}

	// if file got already dumped
	if hasAction(e, ActionFiledump) {
		return
	}

	dumpFilesRtn(h, e)
}

func dumpFilesRtn(h *HIDS, e *event.EdrEvent) {
	var err error

	// make it non blocking
	go func() {
		h.hookSemaphore.Acquire()
		defer h.hookSemaphore.Release()
		guid := srcGUIDFromEvent(e)

		// check if we should go on
		if !h.processTracker.CheckDumpCountOrInc(guid, h.config.Dump.MaxDumps, h.config.Dump.DumpUntracked) {
			log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
			return
		}

		// build up dump path
		dumpPath := filepath.Join(h.config.Dump.Dir, guid, e.Hash())
		// dump event who triggered the dump
		dumpEventAndCompress(h, e, guid)

		// dump CommandLine fields regardless of the event
		// this would actually work best when hooks are enabled and enrichment occurs
		// in the worst case it would only work for Sysmon CreateProcess events
		dumpCommandLine(h, e, dumpPath)
		dumpParentCommandLine(h, e, dumpPath)

		// Handling different kinds of event IDs
		switch e.EventID() {

		case SysmonFileTime, SysmonFileCreate, SysmonCreateStreamHash:
			if target, ok := e.GetString(pathSysmonTargetFilename); ok {
				if err = dumpFileAndCompress(h, target, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), target, ok)
				}
			}

		case SysmonDriverLoad:
			if im, ok := e.GetString(pathSysmonImageLoaded); ok {
				if err = dumpFileAndCompress(h, im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, ok)
				}
			}

		case SysmonAccessProcess:
			if sim, ok := e.GetString(pathSysmonSourceImage); ok {
				if err = dumpFileAndCompress(h, sim, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), sim, ok)
				}
			}

		case SysmonRegSetValue, SysmonWMIConsumer:
			// for event ID 13
			path := pathSysmonDetails
			if e.EventID() == SysmonWMIConsumer {
				path = pathSysmonDestination
			}
			if cl, ok := e.GetString(path); ok {
				// try to parse details as a command line
				if argv, err := utils.ArgvFromCommandLine(cl); err == nil {
					for _, arg := range argv {
						if fsutil.IsFile(arg) && !utils.IsPipePath(arg) {
							if err = dumpFileAndCompress(h, arg, dumpPath); err != nil {
								log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), arg, err)
							}
						}
					}
				}
			}

		case SysmonFileDelete:
			if im, ok := e.GetString(pathSysmonImage); ok {
				if err = dumpFileAndCompress(h, im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}

			archived, ok := e.GetBool(pathSysmonArchived)
			if ok && archived {
				if !fsutil.IsDir(h.config.Sysmon.ArchiveDirectory) {
					log.Errorf("Aborting deleted file dump: %s archive directory does not exist", h.config.Sysmon.ArchiveDirectory)
					return
				}
				log.Info("Will try to dump deleted file")
				if hashes, ok := e.GetString(pathSysmonHashes); ok {
					if target, ok := e.GetString(pathSysmonTargetFilename); ok {
						fname := fmt.Sprintf("%s%s", sysmonArcFileRe.ReplaceAllString(hashes, ""), filepath.Ext(target))
						path := filepath.Join(h.config.Sysmon.ArchiveDirectory, fname)
						if err = dumpFileAndCompress(h, path, dumpPath); err != nil {
							log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), path, ok)
						}
					}
				}
			}

		default:
			if im, ok := e.GetString(pathSysmonImage); ok {
				if err = dumpFileAndCompress(h, im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}
			if pim, ok := e.GetString(pathSysmonParentImage); ok {
				if err = dumpFileAndCompress(h, pim, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), pim, err)
				}
			}
		}
	}()
}

func hookDumpReport(h *HIDS, e *event.EdrEvent) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if h.IsHIDSEvent(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < h.config.Dump.Treshold {
		return
	}

	// if file got already dumped
	if hasAction(e, ActionReport) {
		return
	}

	dumpReportRtn(h, e)
}

func dumpReportRtn(h *HIDS, e *event.EdrEvent) {
	// make it non blocking
	go func() {
		h.hookSemaphore.Acquire()
		defer h.hookSemaphore.Release()

		c := h.config.Report
		guid := srcGUIDFromEvent(e)

		// check if we should go on
		if !h.processTracker.CheckDumpCountOrInc(guid, h.config.Dump.MaxDumps, h.config.Dump.DumpUntracked) {
			log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
			return
		}
		reportPath := dumpPrepareDumpFilename(e, h.config.Dump.Dir, guid, "report.json")
		//psPath := dumpPrepareDumpFilename(e, h.config.Dump.Dir, guid, "ps.json")
		dumpEventAndCompress(h, e, guid)
		if c.EnableReporting {
			log.Infof("Generating IR report: %s", guid)
			if b, err := json.Marshal(h.Report()); err != nil {
				log.Errorf("Failed to JSON encode report: %s", guid)
			} else {
				utils.HidsWriteFile(reportPath, b)
				h.compress(reportPath)
			}
			log.Infof("Finished generating report: %s", guid)
		}

	}()
}
