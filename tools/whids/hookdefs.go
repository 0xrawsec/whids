package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/0xrawsec/gene/engine"
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

func terminate(pid int) error {
	// prevents from terminating our own process
	if os.Getpid() != pid {
		pHandle, err := kernel32.OpenProcess(kernel32.PROCESS_ALL_ACCESS, win32.FALSE, win32.DWORD(pid))
		if err != nil {
			return err
		}
		err = syscall.TerminateProcess(syscall.Handle(pHandle), 0)
		if err != nil {
			return err
		}
	}
	return nil
}

/////////////////////////// ProcessTracker ////////////////////////////////

type stats struct {
	CountProcessCreated    int64
	CountNetConn           int64
	CountFilesCreated      int64
	CountFilesCreatedByExt map[string]int64
	TimeFirstFileCreated   time.Time
	TimeLastFileCreated    time.Time
	CountFilesDeleted      int64
	CountFilesDeletedByExt map[string]int64
	TimeFirstFileDeleted   time.Time
	TimeLastFileDeleted    time.Time
}

func NewStats() stats {
	return stats{
		CountFilesCreatedByExt: make(map[string]int64),
		CountFilesDeletedByExt: make(map[string]int64),
	}
}

type processTrack struct {
	Image                  string
	ParentImage            string
	PID                    int64
	CommandLine            string
	ParentCommandLine      string
	CurrentDirectory       string
	ParentCurrentDirectory string
	ProcessGUID            string
	User                   string
	ParentUser             string
	IntegrityLevel         string
	ParentIntegrityLevel   string
	ParentProcessGUID      string
	Services               string
	ParentServices         string
	Hashes                 string
	Signature              string
	SignatureStatus        string
	Signed                 bool
	History                []string
	Integrity              float64
	IntegrityTimeout       bool
	IntegrityComputed      bool
	Stats                  stats
	MemDumped              bool
	DumpsCount             int
	TimeTerminated         time.Time
}

func NewProcessTrack() *processTrack {
	return &processTrack{
		Signature:       "?",
		SignatureStatus: "?",
		History:         make([]string, 0),
		Integrity:       -1.0,
		Stats:           NewStats(),
	}
}

func (t *processTrack) IsTerminated() bool {
	return !t.TimeTerminated.IsZero()
}

func (t *processTrack) TerminateProcess() error {
	if !t.IsTerminated() {
		return terminate(int(t.PID))
	}
	return nil
}

type ProcessTracker struct {
	sync.RWMutex
	guids       map[string]*processTrack
	pids        map[int64]*processTrack
	blacklisted datastructs.SyncedSet
	free        *datastructs.Fifo
}

func NewProcessTracker() *ProcessTracker {
	pt := &ProcessTracker{
		guids:       make(map[string]*processTrack),
		pids:        make(map[int64]*processTrack),
		blacklisted: datastructs.NewSyncedSet(),
		free:        &datastructs.Fifo{},
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

// returns true if DumpCount member of processTrack is below max argument
// and increments if necessary. This function is used to check whether we
// should still dump information given a guid
func (pt *ProcessTracker) CheckDumpCountOrInc(guid string, max int, deflt bool) bool {
	pt.Lock()
	defer pt.Unlock()
	if track, ok := pt.guids[guid]; ok {
		if track.DumpsCount < max {
			track.DumpsCount++
			return true
		}
		return false
	}
	// we return a parametrized default value (cleaner than returning global)
	return deflt
}

func (pt *ProcessTracker) Add(t *processTrack) {
	pt.Lock()
	defer pt.Unlock()
	pt.guids[t.ProcessGUID] = t
	pt.pids[t.PID] = t
}

func (pt *ProcessTracker) Blacklist(cmdLine string) {
	pt.blacklisted.Add(cmdLine)
}

func (pt *ProcessTracker) IsBlacklisted(cmdLine string) bool {
	return pt.blacklisted.Contains(cmdLine)
}

func (pt *ProcessTracker) GetParentByGuid(guid string) *processTrack {
	pt.RLock()
	defer pt.RUnlock()
	if c, ok := pt.guids[guid]; ok {
		return pt.guids[c.ParentProcessGUID]
	}
	return nil
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

func (pt *ProcessTracker) IsTerminated(guid string) bool {
	if t := pt.GetByGuid(guid); t != nil {
		return t.IsTerminated()
	}
	return true
}

func (pt *ProcessTracker) Terminate(guid string) error {
	if t := pt.GetByGuid(guid); t != nil {
		t.TimeTerminated = time.Now()
		pt.free.Push(t)
	}
	return nil
}

func (pt *ProcessTracker) TerminateProcess(guid string) error {
	if t := pt.GetByGuid(guid); t != nil {
		// We terminate process only if not already terminated
		t.TerminateProcess()
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

const (
	_ = 1 << (iota * 10)
	Kilo
	Mega
)

const (
	// Sysmon Event IDs
	_ = iota
	IDProcessCreate
	IDFileTime
	IDNetworkConnect
	IDServiceStateChange
	IDProcessTerminate
	IDDriverLoad
	IDImageLoad
	IDCreateRemoteThread
	IDRawAccessRead
	IDAccessProcess
	IDFileCreate
	IDRegKey
	IDRegSetValue
	IDRegName
	IDCreateStreamHash
	IDServiceConfigurationChange
	IDCreateNamedPipe
	IDConnectNamedPipe
	IDWMIFilter
	IDWMIConsumer
	IDWMIBinding
	IDDNSQuery
	IDFileDelete
	IDClipboardChange
	IDProcessTampering
	IDFileDeleteDetected

	// Empty GUID
	nullGUID = "{00000000-0000-0000-0000-000000000000}"
)

const (
	// Actions
	ActionMemdump  = "memdump"
	ActionFiledump = "filedump"
	ActionRegdump  = "regdump"
)

var (
	// Globals needed by Hooks
	dumpDirectory          string
	selfGUID               string
	sysmonArchiveDirectory string
	bootCompleted          bool
	flagProcTermEn         bool // set the flag to true if process termination is enabled
	flagDumpCompress       bool
	flagDumpUntracked      bool
	maxDumps               int

	selfPath, _ = filepath.Abs(os.Args[0])
	selfPid     = os.Getpid()

	cryptoLockerFilecreateLimit = int64(50)
	dumpTresh                   = 8
)

var (
	// SysmonChannel Sysmon windows event log channel
	SysmonChannel = "Microsoft-Windows-Sysmon/Operational"
	// SecurityChannel Security windows event log channel
	SecurityChannel = "Security"

	// Filters definitions
	fltAnyEvent        = hooks.NewFilter([]int64{}, "")
	fltAnySysmon       = hooks.NewFilter([]int64{}, SysmonChannel)
	fltProcessCreate   = hooks.NewFilter([]int64{1}, SysmonChannel)
	fltNetworkConnect  = hooks.NewFilter([]int64{3}, SysmonChannel)
	fltProcTermination = hooks.NewFilter([]int64{5}, SysmonChannel)
	fltImageLoad       = hooks.NewFilter([]int64{7}, SysmonChannel)
	fltProcessAccess   = hooks.NewFilter([]int64{10}, SysmonChannel)
	fltRegSetValue     = hooks.NewFilter([]int64{13}, SysmonChannel)
	fltNetwork         = hooks.NewFilter([]int64{3, 22}, SysmonChannel)
	fltImageSize       = hooks.NewFilter([]int64{1, 6, 7}, SysmonChannel)
	fltStats           = hooks.NewFilter([]int64{1, 3, 11, 23, 26}, SysmonChannel)
	fltDNS             = hooks.NewFilter([]int64{22}, SysmonChannel)
	fltClipboard       = hooks.NewFilter([]int64{24}, SysmonChannel)
	fltImageTampering  = hooks.NewFilter([]int64{25}, SysmonChannel)

	fltFSObjectAccess = hooks.NewFilter([]int64{4663}, SecurityChannel)
)

var (
	// Path definitions
	////////////////////////// Getters ///////////////////////////
	// DNS-Client logs
	pathDNSQueryValue   = evtx.Path("/Event/EventData/QueryName")
	pathDNSQueryType    = evtx.Path("/Event/EventData/QueryType")
	pathDNSQueryResults = evtx.Path("/Event/EventData/QueryResults")

	// FileSystemAudit logs
	pathFSAuditProcessId = pathSysmonProcessId

	// Sysmon related paths
	pathSysmonDestIP            = evtx.Path("/Event/EventData/DestinationIp")
	pathSysmonDestHostname      = evtx.Path("/Event/EventData/DestinationHostname")
	pathSysmonImage             = evtx.Path("/Event/EventData/Image")
	pathSysmonHashes            = evtx.Path("/Event/EventData/Hashes")
	pathSysmonCommandLine       = evtx.Path("/Event/EventData/CommandLine")
	pathSysmonParentCommandLine = evtx.Path("/Event/EventData/ParentCommandLine")
	pathSysmonParentImage       = evtx.Path("/Event/EventData/ParentImage")
	pathSysmonImageLoaded       = evtx.Path("/Event/EventData/ImageLoaded")
	pathSysmonSignature         = evtx.Path("/Event/EventData/Signature")
	pathSysmonSigned            = evtx.Path("/Event/EventData/Signed")
	pathSysmonSignatureStatus   = evtx.Path("/Event/EventData/SignatureStatus")

	// EventID 8: CreateRemoteThread
	pathSysmonCRTSourceProcessGuid = evtx.Path("/Event/EventData/SourceProcessGuid")
	pathSysmonCRTTargetProcessGuid = evtx.Path("/Event/EventData/TargetProcessGuid")

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
	pathSysmonTargetProcessId   = evtx.Path("/Event/EventData/TargetProcessId")
	pathSysmonTargetFilename    = evtx.Path("/Event/EventData/TargetFilename")
	pathSysmonCurrentDirectory  = evtx.Path("/Event/EventData/CurrentDirectory")
	pathSysmonDetails           = evtx.Path("/Event/EventData/Details")
	pathSysmonDestination       = evtx.Path("/Event/EventData/Destination")
	pathSysmonSourceImage       = evtx.Path("/Event/EventData/SourceImage")
	pathSysmonTargetImage       = evtx.Path("/Event/EventData/TargetImage")
	pathSysmonUser              = evtx.Path("/Event/EventData/User")
	pathSysmonIntegrityLevel    = evtx.Path("/Event/EventData/IntegrityLevel")

	// EventID 22: DNSQuery
	pathQueryName    = evtx.Path("/Event/EventData/QueryName")
	pathQueryResults = evtx.Path("/Event/EventData/QueryResults")

	// EventID 23:
	pathSysmonArchived = evtx.Path("/Event/EventData/Archived")

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
	pathIntegrityTimeout = evtx.Path("/Event/EventData/ProcessIntegrityTimeout")

	// Use to store pathServices information by hook
	pathServices       = evtx.Path("/Event/EventData/Services")
	pathParentServices = evtx.Path("/Event/EventData/ParentServices")
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

	// Used to store Image Hashes information into any Sysmon Event
	pathImageHashes  = evtx.Path("/Event/EventData/ImageHashes")
	pathSourceHashes = evtx.Path("/Event/EventData/SourceHashes")
	pathTargetHashes = evtx.Path("/Event/EventData/TargetHashes")

	// Used to store image signature related information
	pathImageSignature       = evtx.Path("/Event/EventData/ImageSignature")
	pathImageSigned          = evtx.Path("/Event/EventData/ImageSigned")
	pathImageSignatureStatus = evtx.Path("/Event/EventData/ImageSignatureStatus")

	// Use to enrich Clipboard events
	pathSysmonClipboardData = evtx.Path("/Event/EventData/ClipboardData")

	pathFileCount      = evtx.Path("/Event/EventData/Count")
	pathFileCountByExt = evtx.Path("/Event/EventData/CountByExt")
	pathFileExtension  = evtx.Path("/Event/EventData/Extension")
	pathFileFrequency  = evtx.Path("/Event/EventData/FrequencyEPS")
)

var (
	processTracker = NewProcessTracker()

	dnsResolution = make(map[string]string)

	memdumped = datastructs.NewSyncedSet()
	dumping   = datastructs.NewSyncedSet()

	filedumped = datastructs.NewSyncedSet()

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

// helper function which checks if the event belongs to current WHIDS
func isSysmonProcessTerminate(e *evtx.GoEvtxMap) bool {
	return e.Channel() == SysmonChannel && e.EventID() == IDProcessTerminate
}

// hook applying on Sysmon events containing image information and
// adding a new field containing the image size
func hookSetImageSize(e *evtx.GoEvtxMap) {
	var path *evtx.GoEvtxPath
	var modpath *evtx.GoEvtxPath
	switch e.EventID() {
	case IDProcessCreate:
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
			if image, err := e.GetString(&pathSysmonImage); err == nil {
				// make sure that we are taking signature of the image and not
				// one of its DLL
				if image == track.Image {
					if signed, err := e.GetBool(&pathSysmonSigned); err == nil {
						track.Signed = signed
					}
					if signature, err := e.GetString(&pathSysmonSignature); err == nil {
						track.Signature = signature
					}
					if sigStatus, err := e.GetString(&pathSysmonSignatureStatus); err == nil {
						track.SignatureStatus = sigStatus
					}
				}
			}
			e.Set(&pathImageLoadParentImage, track.ParentImage)
			e.Set(&pathImageLoadParentCommandLine, track.ParentCommandLine)
		}
	}
}

// hooks Windows DNS client logs and maintain a domain name resolution table
func hookDNS(e *evtx.GoEvtxMap) {
	if qresults, err := e.GetString(&pathQueryResults); err == nil {
		if qresults != "" && qresults != "-" {
			records := strings.Split(qresults, ";")
			for _, r := range records {
				// check if it is a valid IP
				if net.ParseIP(r) != nil {
					if qvalue, err := e.GetString(&pathQueryName); err == nil {
						dnsResolution[r] = qvalue
					}
				}
			}
		}
	}
}

// hook tracking processes
func hookTrack(e *evtx.GoEvtxMap) {
	// Default values
	e.Set(&pathAncestors, "?")
	e.Set(&pathParentUser, "?")
	e.Set(&pathParentIntegrityLevel, "?")
	e.Set(&pathParentServices, "?")
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
												if hashes, err := e.GetString(&pathSysmonHashes); err == nil {

													track := NewProcessTrack()
													track.Image = image
													track.ParentImage = pImage
													track.CommandLine = commandLine
													track.ParentCommandLine = pCommandLine
													track.CurrentDirectory = cd
													track.PID = pid
													track.User = user
													track.IntegrityLevel = il
													track.ProcessGUID = guid
													track.ParentProcessGUID = pguid
													track.Hashes = hashes

													if parent := processTracker.GetByGuid(pguid); parent != nil {
														track.History = append(parent.History, parent.Image)
														track.ParentUser = parent.User
														track.ParentIntegrityLevel = parent.IntegrityLevel
														track.ParentServices = parent.Services
														track.ParentCurrentDirectory = parent.CurrentDirectory
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
													if track.ParentServices != "" {
														e.Set(&pathParentServices, track.ParentServices)
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
}

// hook managing statistics about some events
func hookStats(e *evtx.GoEvtxMap) {
	// We do not store stats if process termination is not enabled
	if flagProcTermEn {
		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			if pt := processTracker.GetByGuid(guid); pt != nil {
				switch e.EventID() {
				case IDProcessCreate:
					pt.Stats.CountProcessCreated++
				case IDNetworkConnect:
					pt.Stats.CountNetConn++
				case IDFileCreate:
					now := time.Now()

					// Set new fields
					e.Set(&pathFileCount, "?")
					e.Set(&pathFileCountByExt, "?")
					e.Set(&pathFileExtension, "?")

					if pt.Stats.TimeFirstFileCreated.IsZero() {
						pt.Stats.TimeFirstFileCreated = now
					}

					if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
						ext := filepath.Ext(target)
						pt.Stats.CountFilesCreatedByExt[ext]++
						// Setting file count by extension
						e.Set(&pathFileCountByExt, toString(pt.Stats.CountFilesCreatedByExt[ext]))
						// Setting file extension
						e.Set(&pathFileExtension, ext)
					}
					pt.Stats.CountFilesCreated++
					// Setting total file count
					e.Set(&pathFileCount, toString(pt.Stats.CountFilesCreated))
					// Setting frequency
					freq := now.Sub(pt.Stats.TimeFirstFileCreated)
					if freq != 0 {
						eps := pt.Stats.CountFilesCreated * int64(math.Pow10(9)) / freq.Nanoseconds()
						e.Set(&pathFileFrequency, toString(int64(eps)))
					} else {
						e.Set(&pathFileFrequency, toString(0))
					}
					// Finally set last event timestamp
					pt.Stats.TimeLastFileCreated = now

				case IDFileDelete, IDFileDeleteDetected:
					now := time.Now()

					// Set new fields
					e.Set(&pathFileCount, "?")
					e.Set(&pathFileCountByExt, "?")
					e.Set(&pathFileExtension, "?")

					if pt.Stats.TimeFirstFileDeleted.IsZero() {
						pt.Stats.TimeFirstFileDeleted = now
					}

					if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
						ext := filepath.Ext(target)
						pt.Stats.CountFilesDeletedByExt[ext]++
						// Setting file count by extension
						e.Set(&pathFileCountByExt, toString(pt.Stats.CountFilesDeletedByExt[ext]))
						// Setting file extension
						e.Set(&pathFileExtension, ext)
					}
					pt.Stats.CountFilesDeleted++
					// Setting total file count
					e.Set(&pathFileCount, toString(pt.Stats.CountFilesDeleted))

					// Setting frequency
					freq := now.Sub(pt.Stats.TimeFirstFileDeleted)
					if freq != 0 {
						eps := pt.Stats.CountFilesDeleted * int64(math.Pow10(9)) / freq.Nanoseconds()
						e.Set(&pathFileFrequency, toString(int64(eps)))
					} else {
						e.Set(&pathFileFrequency, toString(0))
					}

					// Finally set last event timestamp
					pt.Stats.TimeLastFileDeleted = time.Now()
				}
			}
		}
	}
}

func guidFromEvent(e *evtx.GoEvtxMap) string {
	if uuid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		return uuid
	}
	if uuid, err := e.GetString(&pathSysmonSourceProcessGUID); err == nil {
		return uuid
	}
	if uuid, err := e.GetString(&pathSysmonCRTSourceProcessGuid); err == nil {
		return uuid
	}
	return ""
}

func processTrackFromEvent(e *evtx.GoEvtxMap) *processTrack {
	if uuid := guidFromEvent(e); uuid != "" {
		return processTracker.GetByGuid(uuid)
	}
	return nil
}

func hasAction(e *evtx.GoEvtxMap, action string) bool {
	if i, err := e.Get(&engine.ActionsPath); err == nil {
		if actions, ok := (*i).([]string); ok {
			for _, a := range actions {
				if a == action {
					return true
				}
			}
		}
	}
	return false
}

func hookHandleActions(e *evtx.GoEvtxMap) {
	var kill, memdump bool

	// We have to check that if we are handling one of
	// our event and we don't want to kill ourself
	if isSelf(e) {
		return
	}

	// the only requirement to be able to handle action
	// is to have a process guuid
	if uuid := guidFromEvent(e); uuid != "" {
		if i, err := e.Get(&engine.ActionsPath); err == nil {
			if actions, ok := (*i).([]string); ok {
				for _, action := range actions {
					switch action {
					case "kill":
						kill = true
						if pt := processTrackFromEvent(e); pt != nil {
							// additional check not to suspend agent
							if int(pt.PID) != os.Getpid() {
								// before we kill we suspend the process
								kernel32.SuspendProcess(int(pt.PID))
							}
						}
					case "blacklist":
						if pt := processTrackFromEvent(e); pt != nil {
							// additional check not to blacklist agent
							if int(pt.PID) != os.Getpid() {
								processTracker.Blacklist(pt.CommandLine)
							}
						}
					case ActionMemdump:
						memdump = true
						dumpProcessRtn(e)
					case ActionRegdump:
						dumpRegistryRtn(e)
					case ActionFiledump:
						dumpFilesRtn(e)
					default:
						log.Errorf("Cannot handle %s action as it is unknown", action)
					}
				}
			}

			// handle kill operation after the other actions
			if kill {
				if pt := processTrackFromEvent(e); pt != nil {
					if memdump {
						// Wait we finish dumping before killing the process
						go func() {
							guid := pt.ProcessGUID
							for i := 0; i < 60 && !memdumped.Contains(guid); i++ {
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
	} else {
		log.Errorf("Failed to handle actions for event (channel: %s, id: %d): no process GUID available", e.Channel(), e.EventID())
	}
}

// hook terminating previously blacklisted processes (according to their CommandLine)
func hookTerminator(e *evtx.GoEvtxMap) {
	if e.EventID() == IDProcessCreate {
		if commandLine, err := e.GetString(&pathSysmonCommandLine); err == nil {
			if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
				if processTracker.IsBlacklisted(commandLine) {
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
func hookProcTerm(e *evtx.GoEvtxMap) {
	log.Debug("Process termination events are enabled")
	flagProcTermEn = true
	if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		// Releasing resources
		processTracker.Terminate(guid)
		memdumped.Del(guid)
	}
}

func hookSelfGUID(e *evtx.GoEvtxMap) {
	if selfGUID == "" {
		if e.EventID() == IDProcessCreate {
			// Sometimes it happens that other events are generated before process creation
			// Check parent image first because we launch whids.exe -h to test process termination
			// and we catch it up if we check image first
			if pimage, err := e.GetString(&pathSysmonParentImage); err == nil {
				if pimage == selfPath {
					if pguid, err := e.GetString(&pathSysmonParentProcessGUID); err == nil {
						selfGUID = pguid
						log.Infof("Found self GUID from PGUID: %s", selfGUID)
						return
					}
				}
			}
			if image, err := e.GetString(&pathSysmonImage); err == nil {
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

func isIntegrityComputed(pt *processTrack) bool {
	if pt == nil {
		return false
	}
	return pt.IntegrityComputed
}

func hookFileSystemAudit(e *evtx.GoEvtxMap) {
	e.Set(&pathSysmonCommandLine, "?")
	e.Set(&pathSysmonProcessGUID, nullGUID)
	e.Set(&pathImageHashes, "?")
	if pid, err := e.GetInt(&pathFSAuditProcessId); err == nil {
		if pt := processTracker.GetByPID(pid); pt != nil {
			if pt.CommandLine != "" {
				e.Set(&pathSysmonCommandLine, pt.CommandLine)
			}
			if pt.Hashes != "" {
				e.Set(&pathImageHashes, pt.Hashes)
			}
			if pt.ProcessGUID != "" {
				e.Set(&pathSysmonProcessGUID, pt.ProcessGUID)
			}
		}
	}
}

func hookProcessIntegrityProcTamp(e *evtx.GoEvtxMap) {
	// Default values
	e.Set(&pathProcessIntegrity, toString(-1.0))

	// Sysmon Create Process
	if e.EventID() == IDProcessTampering {
		if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
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
											e.Set(&pathProcessIntegrity, toString(integrity))
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
func hookEnrichServices(e *evtx.GoEvtxMap) {
	// We do this only if we can cleanup resources
	eventID := e.EventID()
	if flagProcTermEn {
		switch eventID {
		case IDDriverLoad, IDWMIBinding, IDWMIConsumer, IDWMIFilter:
			// Nothing to do
			break
		case IDCreateRemoteThread, IDAccessProcess:
			e.Set(&pathSourceServices, "?")
			e.Set(&pathTargetServices, "?")

			sguidPath := &pathSysmonSourceProcessGUID
			tguidPath := &pathSysmonTargetProcessGUID

			if eventID == 8 {
				sguidPath = &pathSysmonCRTSourceProcessGuid
				tguidPath = &pathSysmonCRTTargetProcessGuid
			}

			if sguid, err := e.GetString(sguidPath); err == nil {
				// First try to resolve it by tracked process
				if t := processTracker.GetByGuid(sguid); t != nil {
					e.Set(&pathSourceServices, t.Services)
				} else {
					// If it fails we resolve the services by PID
					if spid, err := e.GetInt(&pathSysmonSourceProcessId); err == nil {
						if svcs, err := advapi32.ServiceWin32NamesByPid(uint32(spid)); err == nil {
							e.Set(&pathSourceServices, svcs)
						} else {
							log.Errorf("Failed to resolve service from PID=%d: %s", spid, err)
						}
					}
				}
			}

			// First try to resolve it by tracked process
			if tguid, err := e.GetString(tguidPath); err == nil {
				if t := processTracker.GetByGuid(tguid); t != nil {
					e.Set(&pathTargetServices, t.Services)
				} else {
					// If it fails we resolve the services by PID
					if tpid, err := e.GetInt(&pathSysmonTargetProcessId); err == nil {
						if svcs, err := advapi32.ServiceWin32NamesByPid(uint32(tpid)); err == nil {
							e.Set(&pathTargetServices, svcs)
						} else {
							log.Errorf("Failed to resolve service from PID=%d: %s", tpid, err)
						}
					}
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
							track = NewProcessTrack()
							track.Image = image
							track.ProcessGUID = guid
							track.PID = pid
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

// hook that replaces the destination hostname of Sysmon Network connection
// event with the one previously found in the DNS logs
func hookEnrichDNSSysmon(e *evtx.GoEvtxMap) {
	if ip, err := e.GetString(&pathSysmonDestIP); err == nil {
		if dom, ok := dnsResolution[ip]; ok {
			e.Set(&pathSysmonDestHostname, dom)
		}
	}
}

// Todo: move this function into evtx package
func eventHas(e *evtx.GoEvtxMap, p *evtx.GoEvtxPath) bool {
	_, err := e.GetString(p)
	return err == nil
}

func hookEnrichAnySysmon(e *evtx.GoEvtxMap) {
	eventID := e.EventID()
	switch eventID {
	case IDProcessCreate, IDDriverLoad:
		// ProcessCreation is already processed in hookTrack
		// DriverLoad does not contain any GUID information
		break

	case IDCreateRemoteThread, IDAccessProcess:
		// Handling CreateRemoteThread and ProcessAccess events
		// Default Values for the fields
		e.Set(&pathSourceUser, "?")
		e.Set(&pathSourceIntegrityLevel, "?")
		e.Set(&pathTargetUser, "?")
		e.Set(&pathTargetIntegrityLevel, "?")
		e.Set(&pathTargetParentProcessGuid, "?")
		e.Set(&pathSourceHashes, "?")
		e.Set(&pathTargetHashes, "?")

		sguidPath := &pathSysmonSourceProcessGUID
		tguidPath := &pathSysmonTargetProcessGUID

		if eventID == IDCreateRemoteThread {
			sguidPath = &pathSysmonCRTSourceProcessGuid
			tguidPath = &pathSysmonCRTTargetProcessGuid
		}

		if sguid, err := e.GetString(sguidPath); err == nil {
			if tguid, err := e.GetString(tguidPath); err == nil {
				if strack := processTracker.GetByGuid(sguid); strack != nil {
					if strack.User != "" {
						e.Set(&pathSourceUser, strack.User)
					}
					if strack.IntegrityLevel != "" {
						e.Set(&pathSourceIntegrityLevel, strack.IntegrityLevel)
					}
					if strack.Hashes != "" {
						e.Set(&pathSourceHashes, strack.Hashes)
					}
				}
				if ttrack := processTracker.GetByGuid(tguid); ttrack != nil {
					if ttrack.User != "" {
						e.Set(&pathTargetUser, ttrack.User)
					}
					if ttrack.IntegrityLevel != "" {
						e.Set(&pathTargetIntegrityLevel, ttrack.IntegrityLevel)
					}
					if ttrack.ParentProcessGUID != "" {
						e.Set(&pathTargetParentProcessGuid, ttrack.ParentProcessGUID)
					}
					if ttrack.Hashes != "" {
						e.Set(&pathTargetHashes, ttrack.Hashes)
					}
				}
			}
		}
		break

	default:

		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
			if track := processTracker.GetByGuid(guid); track != nil {
				// if event does not have CommandLine field
				if !eventHas(e, &pathSysmonCommandLine) {
					e.Set(&pathSysmonCommandLine, "?")
					if track.CommandLine != "" {
						e.Set(&pathSysmonCommandLine, track.CommandLine)
					}
				}

				// if event does not have User field
				if !eventHas(e, &pathSysmonUser) {
					e.Set(&pathSysmonUser, "?")
					if track.User != "" {
						e.Set(&pathSysmonUser, track.User)
					}
				}

				// if event does not have IntegrityLevel field
				if !eventHas(e, &pathSysmonIntegrityLevel) {
					e.Set(&pathSysmonIntegrityLevel, "?")
					if track.IntegrityLevel != "" {
						e.Set(&pathSysmonIntegrityLevel, track.IntegrityLevel)
					}
				}

				// if event does not have CurrentDirectory field
				if !eventHas(e, &pathSysmonCurrentDirectory) {
					e.Set(&pathSysmonCurrentDirectory, "?")
					if track.CurrentDirectory != "" {
						e.Set(&pathSysmonCurrentDirectory, track.CurrentDirectory)
					}
				}

				// event never has ImageHashes field since it is not Sysmon standard
				e.Set(&pathImageHashes, "?")
				if track.Hashes != "" {
					e.Set(&pathImageHashes, track.Hashes)
				}

				// Signature information
				e.Set(&pathImageSigned, toString(track.Signed))
				e.Set(&pathImageSignature, track.Signature)
				e.Set(&pathImageSignatureStatus, track.SignatureStatus)
			}
		}
	}
}

func hookClipboardEvents(e *evtx.GoEvtxMap) {
	e.Set(&pathSysmonClipboardData, "?")
	if hashes, err := e.GetString(&pathSysmonHashes); err == nil {
		fname := fmt.Sprintf("CLIP-%s", sysmonArcFileRe.ReplaceAllString(hashes, ""))
		path := filepath.Join(sysmonArchiveDirectory, fname)
		if fi, err := os.Stat(path); err == nil {
			// limit size of ClipboardData to 1 Mega
			if fi.Mode().IsRegular() && fi.Size() < Mega {
				if data, err := ioutil.ReadFile(path); err == nil {
					// We try to decode utf16 content because regexp can only match utf8
					// Thus doing this is needed to apply detection rule on clipboard content
					if enc, err := utils.Utf16ToUtf8(data); err == nil {
						e.Set(&pathSysmonClipboardData, string(enc))
					} else {
						e.Set(&pathSysmonClipboardData, fmt.Sprintf("%q", data))
					}
				}
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
	if kernel32.IsPIDRunning(pid) && pid != selfPid && !memdumped.Contains(guid) && !dumping.Contains(guid) {

		// To avoid dumping the same process twice, possible if two alerts
		// comes from the same GUID in a short period of time
		dumping.Add(guid)
		defer dumping.Del(guid)

		tmpDumpDir := filepath.Join(dumpDirectory, guid, id)
		os.MkdirAll(tmpDumpDir, defaultPerms)
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
	dst := filepath.Join(path, fmt.Sprintf("%d_%s.bin", time.Now().UnixNano(), base))
	// dump sha256 of file anyway
	ioutil.WriteFile(fmt.Sprintf("%s.sha256", dst), []byte(sha256), 600)
	if !filedumped.Contains(sha256) {
		log.Debugf("Dumping file: %s->%s", src, dst)
		if err = fsutil.CopyFile(src, dst); err == nil {
			compress(dst)
			filedumped.Add(sha256)
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

	if !dumping.Contains(id) && !filedumped.Contains(id) {
		dumping.Add(id)
		defer dumping.Del(id)

		var f *os.File

		f, err = os.Create(dumpPath)
		if err != nil {
			return
		}
		f.Write(evtx.ToJSON(e))
		f.Close()
		compress(dumpPath)
		filedumped.Add(id)
	}
	return
}

//////////////////// Post Detection Hooks /////////////////////

// variables specific to post-detection hooks
var (
	sysmonArcFileRe = regexp.MustCompile("(((SHA1|MD5|SHA256|IMPHASH)=)|,)")
)

func hookDumpProcess(e *evtx.GoEvtxMap) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if isSelf(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < dumpTresh {
		return
	}

	// if memory got already dumped
	if hasAction(e, ActionMemdump) {
		return
	}

	dumpProcessRtn(e)
}

// this hook can run async
func dumpProcessRtn(e *evtx.GoEvtxMap) {

	parallelHooks.Acquire()
	go func() {
		defer parallelHooks.Release()
		var pidPath *evtx.GoEvtxPath
		var procGUIDPath *evtx.GoEvtxPath

		// the interesting pid to dump depends on the event
		switch e.EventID() {
		case IDCreateRemoteThread, IDAccessProcess:
			pidPath = &pathSysmonSourceProcessId
			procGUIDPath = &pathSysmonSourceProcessGUID
		default:
			pidPath = &pathSysmonProcessId
			procGUIDPath = &pathSysmonProcessGUID
		}

		if guid, err := e.GetString(procGUIDPath); err == nil {

			// check if we should go on
			if !processTracker.CheckDumpCountOrInc(guid, maxDumps, flagDumpUntracked) {
				log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
				return
			}

			if pid, err := e.GetInt(pidPath); err == nil {
				dumpEventAndCompress(e, guid)
				dumpPidAndCompress(int(pid), guid, idFromEvent(e))
			}
		}
	}()
}

func hookDumpRegistry(e *evtx.GoEvtxMap) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if isSelf(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < dumpTresh {
		return
	}

	// if registry got already dumped
	if hasAction(e, ActionRegdump) {
		return
	}

	dumpRegistryRtn(e)
}

// ToDo: test this function
func dumpRegistryRtn(e *evtx.GoEvtxMap) {
	parallelHooks.Acquire()
	go func() {
		defer parallelHooks.Release()
		if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {

			// check if we should go on
			if !processTracker.CheckDumpCountOrInc(guid, maxDumps, flagDumpUntracked) {
				log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
				return
			}

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

func dumpCommandLine(e *evtx.GoEvtxMap, dumpPath string) {
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
}

func dumpParentCommandLine(e *evtx.GoEvtxMap, dumpPath string) {
	if guid, err := e.GetString(&pathSysmonProcessGUID); err == nil {
		if track := processTracker.GetByGuid(guid); track != nil {
			if argv, err := utils.ArgvFromCommandLine(track.ParentCommandLine); err == nil {
				if len(argv) > 1 {
					for _, arg := range argv[1:] {
						if fsutil.IsFile(arg) && !utils.IsPipePath(arg) {
							if err = dumpFileAndCompress(arg, dumpPath); err != nil {
								log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), arg, err)
							}
						}
						// try to dump a path relative to parent CWD
						if track.ParentCurrentDirectory != "" {
							relarg := filepath.Join(track.ParentCurrentDirectory, arg)
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
	}
}

func hookDumpFiles(e *evtx.GoEvtxMap) {
	// We have to check that if we are handling one of
	// our event and we don't want to dump ourself
	if isSelf(e) {
		return
	}

	// we dump only if alert is relevant
	if getCriticality(e) < dumpTresh {
		return
	}

	// if file got already dumped
	if hasAction(e, ActionFiledump) {
		return
	}

	dumpFilesRtn(e)
}

func dumpFilesRtn(e *evtx.GoEvtxMap) {
	parallelHooks.Acquire()
	go func() {
		defer parallelHooks.Release()
		guid := nullGUID
		tmpGUID, err := e.GetString(&pathSysmonProcessGUID)
		if err != nil {
			if tmpGUID, err = e.GetString(&pathSysmonSourceProcessGUID); err == nil {
				guid = tmpGUID
			}
		} else {
			guid = tmpGUID
		}

		// check if we should go on
		if !processTracker.CheckDumpCountOrInc(guid, maxDumps, flagDumpUntracked) {
			log.Warnf("Not dumping, reached maximum dumps count for guid %s", guid)
			return
		}

		// build up dump path
		dumpPath := filepath.Join(dumpDirectory, guid, idFromEvent(e))
		// dump event who triggered the dump
		dumpEventAndCompress(e, guid)

		// dump CommandLine fields regardless of the event
		// this would actually work best when hooks are enabled and enrichment occurs
		// in the worst case it would only work for Sysmon CreateProcess events
		dumpCommandLine(e, dumpPath)
		dumpParentCommandLine(e, dumpPath)

		// Handling different kinds of event IDs
		switch e.EventID() {

		case IDFileTime, IDFileCreate, IDCreateStreamHash:
			if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
				if err = dumpFileAndCompress(target, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), target, err)
				}
			}

		case IDDriverLoad:
			if im, err := e.GetString(&pathSysmonImageLoaded); err == nil {
				if err = dumpFileAndCompress(im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}

		case IDAccessProcess:
			if sim, err := e.GetString(&pathSysmonSourceImage); err == nil {
				if err = dumpFileAndCompress(sim, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), sim, err)
				}
			}

		case IDRegSetValue, IDWMIConsumer:
			// for event ID 13
			path := &pathSysmonDetails
			if e.EventID() == IDWMIConsumer {
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

		case IDFileDelete:
			if im, err := e.GetString(&pathSysmonImage); err == nil {
				if err = dumpFileAndCompress(im, dumpPath); err != nil {
					log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), im, err)
				}
			}

			archived, err := e.GetBool(&pathSysmonArchived)
			if err == nil && archived {
				if !fsutil.IsDir(sysmonArchiveDirectory) {
					log.Errorf("Aborting deleted file dump: %s archive directory does not exist", sysmonArchiveDirectory)
					return
				}
				log.Info("Will try to dump deleted file")
				if hashes, err := e.GetString(&pathSysmonHashes); err == nil {
					if target, err := e.GetString(&pathSysmonTargetFilename); err == nil {
						fname := fmt.Sprintf("%s%s", sysmonArcFileRe.ReplaceAllString(hashes, ""), filepath.Ext(target))
						path := filepath.Join(sysmonArchiveDirectory, fname)
						if err = dumpFileAndCompress(path, dumpPath); err != nil {
							log.Errorf("Error dumping file from EventID=%d \"%s\": %s", e.EventID(), path, err)
						}
					}
				}
			}

		default:
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
