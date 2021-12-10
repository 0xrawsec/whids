package hids

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xrawsec/gene/v2/engine"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
)

////////////////////////////////// Hooks //////////////////////////////////

const (
	// Empty GUID
	nullGUID = "{00000000-0000-0000-0000-000000000000}"
)

var (
	selfPath, _ = filepath.Abs(os.Args[0])
)

var (
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

	if t := processTrackFromEvent(h, e); !t.IsZero() {
		if d := e.GetDetection(); d != nil {
			t.ThreatScore.Update(d)
		}
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
				if ppid, ok := e.GetInt(pathSysmonParentProcessId); ok {
					if pimage == selfPath && ppid == int64(os.Getpid()) {
						if pguid, ok := e.GetString(pathSysmonParentProcessGUID); ok {
							h.guid = pguid
							log.Infof("Found self GUID from PGUID: %s", h.guid)
							return
						}
					}
				}
			}
			if image, ok := e.GetString(pathSysmonImage); ok {
				if pid, ok := e.GetInt(pathSysmonProcessId); ok {
					if image == selfPath && pid == int64(os.Getpid()) {
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
}

func hookFileSystemAudit(h *HIDS, e *event.EdrEvent) {
	e.Set(pathSysmonCommandLine, "?")
	e.Set(pathSysmonProcessGUID, nullGUID)
	e.Set(pathSysmonImage, "?")
	e.Set(pathImageHashes, "?")
	if pid, ok := e.GetInt(pathFSAuditProcessId); ok {
		if pt := h.processTracker.GetByPID(pid); pt != nil {

			e.SetIf(pathSysmonImage, pt.Image, pt.Image != "")
			e.SetIf(pathSysmonCommandLine, pt.CommandLine, pt.CommandLine != "")
			e.SetIf(pathImageHashes, pt.hashes, pt.hashes != "")
			e.SetIf(pathSysmonProcessGUID, pt.ProcessGUID, pt.ProcessGUID != "")

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

var (
	pathKernelFileFileObject = engine.Path("/Event/EventData/FileObject")
	pathKernelFileFileName   = engine.Path("/Event/EventData/FileName")
)

func hookKernelFiles(h *HIDS, e *event.EdrEvent) {

	// Enrich all events with Sysmon Info
	pt := h.processTracker.GetByPID(int64(e.Event.System.Execution.ProcessID))

	// We enrich event with other data
	e.SetIfOr(pathSysmonProcessGUID, pt.ProcessGUID, !pt.IsZero(), "?")
	e.SetIfOr(pathSysmonImage, pt.Image, !pt.IsZero(), "?")
	e.SetIfOr(pathSysmonCommandLine, pt.CommandLine, !pt.IsZero(), "?")
	// put hashes in ImageHashes field to avoid confusion in analyst's mind
	// not to think it is file content hashes
	e.SetIfOr(pathImageHashes, pt.hashes, !pt.IsZero(), "?")
	e.SetIfOr(pathSysmonProcessId, toString(pt.PID), !pt.IsZero(), toString(-1))
	e.SetIfOr(pathSysmonIntegrityLevel, pt.IntegrityLevel, !pt.IsZero(), "?")
	e.SetIfOr(pathSysmonUser, pt.User, !pt.IsZero(), "?")
	e.SetIfOr(pathServices, pt.Services, !pt.IsZero(), "?")
	e.Set(pathSysmonEventType, KernelFileOperations[e.EventID()])

	if e.EventID() == KernelFileCreate {
		// We track file
		h.processTracker.AddKernelFile(KernelFileFromEvent(e))
	} else {
		var fo uint64
		var ok bool

		// We correlate with the filename
		if fo, ok = e.GetUint(pathKernelFileFileObject); ok {
			fileName := "?"
			if kf, ok := h.processTracker.GetKernelFile(fo); ok {
				fileName = kf.FileName
			}
			e.Set(pathKernelFileFileName, fileName)
		}
		// We delete entry in tracking structure
		if e.EventID() == KernelFileClose {
			h.processTracker.DelKernelFile(fo)
		}
	}
}
