package agent

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xrawsec/gene/v2/engine"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
)

////////////////////////////////// Hooks //////////////////////////////////

const (
	// Empty GUID
	nullGUID      = "{00000000-0000-0000-0000-000000000000}"
	unkFieldValue = "?"
)

var (
	selfPath, _ = filepath.Abs(os.Args[0])
)

// hook applying on Sysmon events containing image information and
// adding a new field containing the image size

func hookSetImageSize(h *Agent, e *event.EdrEvent) {
	var image string
	var ok bool
	var path *engine.XPath
	var imSzPath *engine.XPath

	switch e.EventID() {
	case SysmonProcessCreate:
		path = pathSysmonImage
		imSzPath = pathImSize
	default:
		path = pathSysmonImageLoaded
		imSzPath = pathImLoadedSize
	}

	if image, ok = e.GetString(path); !ok {
		goto RETURN
	}

	if !fsutil.IsFile(image) {
		goto RETURN
	}

	if stat, err := os.Stat(image); err == nil {
		e.SetIfMissing(imSzPath, toString(stat.Size()))
		return
	}

RETURN:
	e.SetIfMissing(imSzPath, unkFieldValue)
}

func hookImageLoad(h *Agent, e *event.EdrEvent) {
	var ok bool
	var guid string
	var track *ProcessTrack
	var mi *ModuleInfo

	if guid, ok = e.GetString(pathSysmonProcessGUID); !ok {
		goto RETURN
	}

	if track = h.tracker.GetByGuid(guid); track.IsZero() {
		goto RETURN
	}

	// we get a module info from cache or we update
	mi = h.tracker.GetModuleOrUpdate(ModuleInfoFromEvent(e))

	// make sure that we are taking signature of the image and not
	// one of its DLL
	if mi.Image == track.Image {
		track.Signed = mi.Signed
		track.Signature = mi.Signature
		track.SignatureStatus = mi.SignatureStatus
	} else {
		// update module list
		track.Modules = append(track.Modules, mi)
	}

	e.SetIfMissing(pathImageLoadParentImage, track.ParentImage)
	e.SetIfMissing(pathImageLoadParentCommandLine, track.ParentCommandLine)
	return

RETURN:
	e.SetIfMissing(pathImageLoadParentImage, unkFieldValue)
	e.SetIfMissing(pathImageLoadParentCommandLine, unkFieldValue)
}

func trackSysmonProcessCreate(h *Agent, e *event.EdrEvent) {
	var ok bool
	var track *ProcessTrack
	var pid int64
	var guid, image, commandLine, pCommandLine, pImage, pguid, user, il, cd, hashes string

	// We need to be sure that process termination is enabled
	// before initiating process tracking not to fill up memory
	// with structures that will never be freed
	if h.bootCompleted && !h.flagProcTermEn {
		goto DEFAULT
	}

	if guid, ok = e.GetString(pathSysmonProcessGUID); !ok {
		goto DEFAULT
	}

	if pid, ok = e.GetInt(pathSysmonProcessId); !ok {
		goto DEFAULT
	}

	if image, ok = e.GetString(pathSysmonImage); !ok {
		goto DEFAULT
	}

	// Boot sequence is completed when LogonUI.exe is strarted
	if strings.EqualFold(image, "C:\\Windows\\System32\\LogonUI.exe") {
		h.logger.Infof("Boot sequence completed")
		h.bootCompleted = true
	}

	if commandLine, ok = e.GetString(pathSysmonCommandLine); !ok {
		goto DEFAULT
	}

	if pCommandLine, ok = e.GetString(pathSysmonParentCommandLine); !ok {
		goto DEFAULT
	}

	if pImage, ok = e.GetString(pathSysmonParentImage); !ok {
		goto DEFAULT
	}

	if pguid, ok = e.GetString(pathSysmonParentProcessGUID); !ok {
		goto DEFAULT
	}

	if user, ok = e.GetString(pathSysmonUser); !ok {
		goto DEFAULT
	}

	if il, ok = e.GetString(pathSysmonIntegrityLevel); !ok {
		goto DEFAULT
	}

	if cd, ok = e.GetString(pathSysmonCurrentDirectory); !ok {
		goto DEFAULT
	}

	if hashes, ok = e.GetString(pathSysmonHashes); !ok {
		goto DEFAULT
	}

	track = NewProcessTrack(image, pguid, guid, pid)
	track.ParentImage = pImage
	track.CommandLine = commandLine
	track.ParentCommandLine = pCommandLine
	track.CurrentDirectory = cd
	track.User = user
	track.IntegrityLevel = il
	track.SetHashes(hashes)

	// Getting process protection level first
	if pl, err := kernel32.GetProcessProtectionLevel(uint32(pid)); err == nil {
		track.ProtectionLevel = uint32(pl)
	}

	if parent := h.tracker.GetByGuid(pguid); !parent.IsZero() {
		track.Ancestors = append(parent.Ancestors, parent.Image)
		track.ParentUser = parent.User
		track.ParentIntegrityLevel = parent.IntegrityLevel
		track.ParentServices = parent.Services
		track.ParentCurrentDirectory = parent.CurrentDirectory
		track.ParentProtectionLevel = parent.ProtectionLevel
	} else {
		// For processes created by System
		if pimage, ok := e.GetString(pathSysmonParentImage); ok {
			track.Ancestors = append(track.Ancestors, pimage)
			// if parent is System
			if strings.EqualFold(pimage, "System") {
				ptrack := NewProcessTrack(pimage,
					nullGUID, pguid, e.GetIntOr(pathSysmonParentProcessId, -1))
				h.tracker.Add(ptrack)
			}
		}
	}

	h.tracker.Add(track)
	e.SetIfMissing(pathAncestors, strings.Join(track.Ancestors, "|"))
	e.SetIfMissing(pathProtectionLevel, fmt.Sprintf("0x%x", track.ProtectionLevel))
	e.SetIfMissing(pathParentProtectionLevel, fmt.Sprintf("0x%x", track.ParentProtectionLevel))
	if track.ParentUser != "" {
		e.SetIfMissing(pathParentUser, track.ParentUser)
	}
	if track.ParentIntegrityLevel != "" {
		e.SetIfMissing(pathParentIntegrityLevel, track.ParentIntegrityLevel)
	}

	if track.ParentServices != "" {
		e.SetIfMissing(pathParentServices, track.ParentServices)
	}

DEFAULT:
	// Default values
	e.SetIfMissing(pathAncestors, unkFieldValue)
	e.SetIfMissing(pathParentUser, unkFieldValue)
	e.SetIfMissing(pathParentIntegrityLevel, unkFieldValue)
	e.SetIfMissing(pathParentServices, unkFieldValue)
}

// hook tracking processes
func hookTrack(h *Agent, e *event.EdrEvent) {
	switch e.EventID() {
	case SysmonProcessCreate:
		// moved to a function to make code cleaner
		trackSysmonProcessCreate(h, e)

	case SysmonDriverLoad:
		d := DriverInfoFromEvent(e)
		h.tracker.Drivers = append(h.tracker.Drivers, *d)
	}
}

// hook managing statistics about some events
func hookStats(h *Agent, e *event.EdrEvent) {
	// We do not store stats if process termination is not enabled
	if !h.flagProcTermEn {
		return
	}

	if pt := h.tracker.SourceTrackFromEvent(e); !pt.IsZero() {
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
			e.Set(pathFileCount, unkFieldValue)
			e.Set(pathFileCountByExt, unkFieldValue)
			e.Set(pathFileExtension, unkFieldValue)

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
			e.Set(pathFileCount, unkFieldValue)
			e.Set(pathFileCountByExt, unkFieldValue)
			e.Set(pathFileExtension, unkFieldValue)

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

// hook updating a threat score by process
func hookUpdateGeneScore(h *Agent, e *event.EdrEvent) {
	var t *ProcessTrack

	if h.IsHIDSEvent(e) {
		return
	}

	if t = h.tracker.SourceTrackFromEvent(e); t.IsZero() {
		return
	}

	if d := e.GetDetection(); d != nil {
		t.ThreatScore.Update(d)
	}
}

// hook terminating previously blacklisted processes (according to their CommandLine)
func hookTerminator(h *Agent, e *event.EdrEvent) {
	var commandLine string
	var pid int64
	var ok bool

	if e.EventID() != SysmonProcessCreate {
		return
	}

	if commandLine, ok = e.GetString(pathSysmonCommandLine); !ok {
		return
	}

	if pid, ok = e.GetInt(pathSysmonProcessId); !ok {
		return
	}

	// terminate if blacklisted
	if h.tracker.IsBlacklisted(commandLine) {
		h.logger.Warnf("Terminating blacklisted  process PID=%d CommandLine=\"%s\"", pid, commandLine)
		if err := terminate(int(pid)); err != nil {
			h.logger.Errorf("Failed to terminate process PID=%d: %s", pid, err)
		}
	}
}

// hook setting flagProcTermEn variable
// it is also used to cleanup any structures needing to be cleaned
func hookProcTerm(h *Agent, e *event.EdrEvent) {
	var guid string
	var ok bool

	h.logger.Debug("Process termination events are enabled")
	h.flagProcTermEn = true

	if guid, ok = e.GetString(pathSysmonProcessGUID); !ok {
		return
	}

	// Releasing resources
	h.tracker.Terminate(guid)
	h.memdumped.Del(guid)
}

func hookSelfGUID(h *Agent, e *event.EdrEvent) {
	// no need to continue if EDR guid is already known
	if h.guid != "" {
		return
	}

	// Sometimes it happens that other events are generated before process creation
	// Check parent image first because we launch whids.exe -h to test process termination
	// and we catch it up if we check image first
	if pimage, ok := e.GetString(pathSysmonParentImage); ok {
		if ppid, ok := e.GetInt(pathSysmonParentProcessId); ok {
			if pimage == selfPath && ppid == int64(os.Getpid()) {
				if pguid, ok := e.GetString(pathSysmonParentProcessGUID); ok {
					h.guid = pguid
					h.logger.Infof("Found self GUID from PGUID: %s", h.guid)
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
					h.logger.Infof("Found self GUID: %s", h.guid)
					return
				}
			}
		}
	}
}

func hookFileSystemAudit(h *Agent, e *event.EdrEvent) {
	var ok bool
	var pid int64
	var pt *ProcessTrack

	e.SetIfMissing(pathSysmonProcessGUID, nullGUID)
	e.SetIfMissing(pathSysmonCommandLine, unkFieldValue)
	e.SetIfMissing(pathSysmonImage, unkFieldValue)
	e.SetIfMissing(pathImageHashes, unkFieldValue)

	if pid, ok = e.GetInt(pathFSAuditProcessId); !ok {
		return
	}

	if pt = h.tracker.GetByPID(pid); pt.IsZero() {
		return
	}

	e.SetIf(pathSysmonImage, pt.Image, pt.Image != "")
	e.SetIf(pathSysmonCommandLine, pt.CommandLine, pt.CommandLine != "")
	e.SetIf(pathImageHashes, pt.imageHashes, pt.imageHashes != "")
	e.SetIf(pathSysmonProcessGUID, pt.ProcessGUID, pt.ProcessGUID != "")

	if obj, ok := e.GetString(pathFSAuditObjectName); ok {
		if fsutil.IsFile(obj) {
			pt.Stats.Files.LastAccessed.Add(obj)
		}
	}
}

func hookProcessIntegrityProcTamp(h *Agent, e *event.EdrEvent) {
	var ok bool
	var pid int64
	var mainTid int

	// Default values
	e.SetIfMissing(pathProcessIntegrity, toString(-1.0))

	// if not Sysmon Process Tampering event
	if e.EventID() != SysmonProcessTampering {
		return
	}

	// getting pid from event
	if pid, ok = e.GetInt(pathSysmonProcessId); !ok {
		return
	}

	// prevents stopping ourselves
	if pid == int64(os.Getpid()) {
		return
	}

	if !kernel32.IsPIDRunning(int(pid)) {
		h.logger.Errorf("Cannot check process integrity process with PID=%d is stopped", pid)
		return
	}

	if mainTid = kernel32.GetFirstTidOfPid(int(pid)); mainTid < 0 {
		return
	}

	// if we found the main thread of pid
	hThread, err := kernel32.OpenThread(kernel32.THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(mainTid))
	if err != nil {
		h.logger.Errorf("Cannot open main thread before checking integrity of PID=%d", pid)
		return
	}
	// close thread
	defer kernel32.CloseHandle(hThread)

	// we first need to wait main process thread
	if ok := kernel32.WaitThreadRuns(hThread, time.Millisecond*50, time.Millisecond*500); !ok {
		// We check whether the thread still exists
		checkThread, err := kernel32.OpenThread(kernel32.PROCESS_SUSPEND_RESUME, win32.FALSE, win32.DWORD(mainTid))
		if err == nil {
			h.logger.Warnf("Timeout reached while waiting main thread of PID=%d", pid)
		}
		// close thread
		kernel32.CloseHandle(checkThread)
		return
	}

	da := win32.DWORD(kernel32.PROCESS_VM_READ | kernel32.PROCESS_QUERY_INFORMATION)
	hProcess, err := kernel32.OpenProcess(da, win32.FALSE, win32.DWORD(pid))

	if err != nil {
		h.logger.Errorf("Cannot open process to check integrity of PID=%d: %s", pid, err)
		return
	}
	// close process
	defer kernel32.CloseHandle(hProcess)

	bdiff, slen, err := kernel32.CheckProcessIntegrity(hProcess)
	if err != nil {
		h.logger.Errorf("Cannot check integrity of PID=%d: %s", pid, err)
		return
	}

	if slen != 0 {
		integrity := utils.Round(float64(bdiff)*100/float64(slen), 2)
		e.Set(pathProcessIntegrity, toString(integrity))
	}
}

// too big to be put in hookEnrichAnySysmon
func hookEnrichServices(h *Agent, e *event.EdrEvent) {
	var err error

	// We do this only if we can cleanup resources
	eventID := e.EventID()

	if !h.flagProcTermEn {
		return
	}

	switch eventID {
	case SysmonDriverLoad, SysmonWMIBinding, SysmonWMIConsumer, SysmonWMIFilter:
		// Nothing to do
		return

	case SysmonCreateRemoteThread, SysmonAccessProcess:
		// First try to resolve it by tracked process
		if src := h.tracker.SourceTrackFromEvent(e); !src.IsZero() {
			e.Set(pathSourceServices, src.Services)
		} else {
			// If it fails we resolve the services by PID
			if spid, ok := e.GetInt(pathSysmonSourceProcessId); ok {
				if svcs, err := advapi32.ServiceWin32NamesByPid(uint32(spid)); err == nil {
					e.Set(pathSourceServices, svcs)
				} else {
					h.logger.Errorf("Failed to resolve service from PID=%d: %s", spid, err)
				}
			}
		}

		// First try to resolve it by tracked process
		if t := h.tracker.TargetTrackFromEvent(e); !t.IsZero() {
			e.Set(pathTargetServices, t.Services)
		} else {
			// If it fails we resolve the services by PID
			if tpid, ok := e.GetInt(pathSysmonTargetProcessId); ok {
				if svcs, err := advapi32.ServiceWin32NamesByPid(uint32(tpid)); err == nil {
					e.Set(pathTargetServices, svcs)
				} else {
					h.logger.Errorf("Failed to resolve service from PID=%d: %s", tpid, err)
				}
			}
		}

		// Default
		e.SetIfMissing(pathSourceServices, unkFieldValue)
		e.SetIfMissing(pathTargetServices, unkFieldValue)

	default:
		// try to resolve by track
		if track := h.tracker.SourceTrackFromEvent(e); !track.IsZero() {
			if track.Services == "" {
				track.Services, err = advapi32.ServiceWin32NamesByPid(uint32(track.PID))
				if err != nil {
					h.logger.Errorf("Failed to resolve service from PID=%d Image=%s", track.PID, track.Image)
					track.Services = unkFieldValue
				}
			}
			e.Set(pathServices, track.Services)
			return
		}

		// image, guid and pid are supposed to be available for all the remaining Sysmon logs
		if pid, ok := e.GetInt(pathSysmonProcessId); ok {
			services, err := advapi32.ServiceWin32NamesByPid(uint32(pid))
			if err != nil {
				h.logger.Errorf("Failed to resolve service from PID=%d: %s", pid, err)
				services = unkFieldValue
			}
			e.Set(pathServices, services)
			return
		}

		// Default
		e.SetIfMissing(pathServices, unkFieldValue)
	}
}

func hookEnrichAnySysmon(h *Agent, e *event.EdrEvent) {
	eventID := e.EventID()
	switch eventID {
	case SysmonProcessCreate, SysmonDriverLoad:
		// ProcessCreation is already processed in hookTrack
		// DriverLoad does not contain any GUID information
		break

	case SysmonCreateRemoteThread, SysmonAccessProcess:
		// Handling CreateRemoteThread and ProcessAccess events

		// source process processing
		if strack := h.tracker.SourceTrackFromEvent(e); !strack.IsZero() {
			if strack.User != "" {
				e.SetIfMissing(pathSourceUser, strack.User)
			}

			if strack.IntegrityLevel != "" {
				e.SetIfMissing(pathSourceIntegrityLevel, strack.IntegrityLevel)
			}

			if strack.imageHashes != "" {
				e.SetIfMissing(pathSourceHashes, strack.imageHashes)
			}

			// Source Protection level
			e.SetIfMissing(pathSourceProtectionLevel, toHex(strack.ProtectionLevel))

			// Source process score
			e.Set(pathSrcProcessGeneScore, toString(strack.ThreatScore.Score))
		}

		// target process processing
		if ttrack := h.tracker.TargetTrackFromEvent(e); !ttrack.IsZero() {
			if ttrack.User != "" {
				e.SetIfMissing(pathTargetUser, ttrack.User)
			}
			if ttrack.IntegrityLevel != "" {
				e.SetIfMissing(pathTargetIntegrityLevel, ttrack.IntegrityLevel)
			}
			if ttrack.ParentProcessGUID != "" {
				e.SetIfMissing(pathTargetParentProcessGuid, ttrack.ParentProcessGUID)
			}
			if ttrack.imageHashes != "" {
				e.SetIfMissing(pathTargetHashes, ttrack.imageHashes)
			}

			e.SetIfMissing(pathTargetProtectionLevel, toHex(ttrack.ProtectionLevel))

			// Target process score
			e.Set(pathTgtProcessGeneScore, toString(ttrack.ThreatScore.Score))
		}

		// Default Values for fields
		e.SetIfMissing(pathSourceUser, unkFieldValue)
		e.SetIfMissing(pathSourceIntegrityLevel, unkFieldValue)
		e.SetIfMissing(pathTargetUser, unkFieldValue)
		e.SetIfMissing(pathTargetIntegrityLevel, unkFieldValue)
		e.SetIfMissing(pathTargetParentProcessGuid, unkFieldValue)
		e.SetIfMissing(pathSourceHashes, unkFieldValue)
		e.SetIfMissing(pathTargetHashes, unkFieldValue)
		e.SetIfMissing(pathSourceProtectionLevel, toHex(ZeroProtectionLevel))
		e.SetIfMissing(pathTargetProtectionLevel, toHex(ZeroProtectionLevel))
		e.SetIfMissing(pathSrcProcessGeneScore, "-1")
		e.SetIfMissing(pathTgtProcessGeneScore, "-1")

	default:

		if track := h.tracker.SourceTrackFromEvent(e); !track.IsZero() {

			// setting CommandLine field
			if track.CommandLine != "" {
				e.SetIfMissing(pathSysmonCommandLine, track.CommandLine)
			}

			// setting User field
			if track.User != "" {
				e.SetIfMissing(pathSysmonUser, track.User)
			}

			// setting IntegrityLevel
			if track.IntegrityLevel != "" {
				e.SetIfMissing(pathSysmonIntegrityLevel, track.IntegrityLevel)
			}

			// setting CurrentDirectory
			if track.CurrentDirectory != "" {
				e.SetIfMissing(pathSysmonCurrentDirectory, track.CurrentDirectory)
			}

			// event never has ImageHashes field since it is not Sysmon standard
			if track.imageHashes != "" {
				e.Set(pathImageHashes, track.imageHashes)
			}

			// Signature information
			e.SetIfMissing(pathImageSigned, toString(track.Signed))
			e.SetIfMissing(pathImageSignature, track.Signature)
			e.SetIfMissing(pathImageSignatureStatus, track.SignatureStatus)

			// Protection level
			e.SetIfMissing(pathProtectionLevel, toHex(track.ProtectionLevel))

			// Overal criticality score
			e.Set(pathProcessGeneScore, toString(track.ThreatScore.Score))
		}

		// Setting GeneScore only if we can identify process by its GUID
		// Default values
		e.SetIfMissing(pathProcessGeneScore, "-1")
		e.SetIfMissing(pathSysmonCommandLine, unkFieldValue)
		e.SetIfMissing(pathSysmonUser, unkFieldValue)
		e.SetIfMissing(pathSysmonIntegrityLevel, unkFieldValue)
		e.SetIfMissing(pathSysmonCurrentDirectory, unkFieldValue)
		e.SetIfMissing(pathImageHashes, unkFieldValue)
		e.SetIfMissing(pathImageSigned, unkFieldValue)
		e.SetIfMissing(pathImageSignature, unkFieldValue)
		e.SetIfMissing(pathImageSignatureStatus, unkFieldValue)
		e.SetIfMissing(pathProtectionLevel, toHex(ZeroProtectionLevel))
	}
}

func hookClipboardEvents(h *Agent, e *event.EdrEvent) {
	e.Set(pathSysmonClipboardData, unkFieldValue)
	if hashes, ok := e.GetString(pathSysmonHashes); ok {
		fname := fmt.Sprintf("CLIP-%s", sysmonArcFileRe.ReplaceAllString(hashes, ""))
		path := filepath.Join(h.config.Sysmon.ArchiveDirectory, fname)
		if fi, err := os.Stat(path); err == nil {
			// limit size of ClipboardData to 1 Mega
			if fi.Mode().IsRegular() && fi.Size() < utils.Mega {
				if data, err := os.ReadFile(path); err == nil {
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

func hookKernelFiles(h *Agent, e *event.EdrEvent) {
	var ok bool
	var fileName string

	// Enrich all events with Sysmon Info
	pt := h.tracker.GetByPID(int64(e.Event.System.Execution.ProcessID))

	// update list of last accessed files
	if fileName, ok = e.GetString(pathSysmonTargetFilename); ok && !pt.IsZero() {
		pt.Stats.Files.LastAccessed.Add(fileName)
	}

	// We enrich event with other data
	e.SetIfOr(pathSysmonProcessGUID, pt.ProcessGUID, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathSysmonImage, pt.Image, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathSysmonCommandLine, pt.CommandLine, !pt.IsZero(), unkFieldValue)
	// put hashes in ImageHashes field to avoid confusion in analyst's mind
	// not to think it is file content hashes
	e.SetIfOr(pathImageHashes, pt.imageHashes, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathSysmonProcessId, toString(pt.PID), !pt.IsZero(), toString(-1))
	e.SetIfOr(pathSysmonIntegrityLevel, pt.IntegrityLevel, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathSysmonUser, pt.User, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathServices, pt.Services, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathImageSignature, pt.Signature, !pt.IsZero(), unkFieldValue)
	e.SetIfOr(pathImageSignatureStatus, pt.SignatureStatus, !pt.IsZero(), unkFieldValue)
	e.Set(pathSysmonEventType, KernelFileOperations[e.EventID()])

	/*fileName := unkFieldValue

	// Enrich all events with Sysmon Info
	pt := h.tracker.GetByPID(int64(e.Event.System.Execution.ProcessID))

	if e.EventID() == KernelFileCreate {
		// We track file
		kf := KernelFileFromEvent(e)
		// we actually resolve drive letters
		h.tracker.AddKernelFile(kf)
		e.Set(pathKernelFileFileName, kf.FileName)
		// to be able to update list of last accessed files
		fileName = kf.FileName
	} else {
		var fo uint64
		var ok bool

		// We correlate with the filename
		if fo, ok = e.GetUint(pathKernelFileFileObject); ok {
			if kf, ok := h.tracker.GetKernelFile(fo); ok {
				fileName = kf.FileName

				// if we are dealing with a file read or a file write
				if e.EventID() == KernelFileRead || e.EventID() == KernelFileWrite {
					// we skip event if we have already reported one
					if kf.EventCount[e.EventID()] > 0 {
						e.Skip()
					}
				}

				// we update event count
				kf.EventCount[e.EventID()]++
			}
			e.Set(pathKernelFileFileName, fileName)
		}

		// We delete entry in tracking structure
		if e.EventID() == KernelFileClose {
			h.tracker.DelKernelFile(fo)
		}
	}

	// update the list of last accessed files
	if fsutil.IsFile(fileName) && !pt.IsZero() {
		pt.Stats.Files.LastAccessed.Add(fileName)
	}

	if !e.IsSkipped() {
		// We enrich event with other data
		e.SetIfOr(pathSysmonProcessGUID, pt.ProcessGUID, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathSysmonImage, pt.Image, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathSysmonCommandLine, pt.CommandLine, !pt.IsZero(), unkFieldValue)
		// put hashes in ImageHashes field to avoid confusion in analyst's mind
		// not to think it is file content hashes
		e.SetIfOr(pathImageHashes, pt.hashes, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathSysmonProcessId, toString(pt.PID), !pt.IsZero(), toString(-1))
		e.SetIfOr(pathSysmonIntegrityLevel, pt.IntegrityLevel, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathSysmonUser, pt.User, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathServices, pt.Services, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathImageSignature, pt.Signature, !pt.IsZero(), unkFieldValue)
		e.SetIfOr(pathImageSignatureStatus, pt.SignatureStatus, !pt.IsZero(), unkFieldValue)
		e.Set(pathSysmonEventType, KernelFileOperations[e.EventID()])
	}*/
}
