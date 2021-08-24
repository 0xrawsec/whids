package hids

import (
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/whids/event"
)

type ConStat struct {
	FirstSeen string          `json:"first-seen"`
	LastSeen  string          `json:"last-seen"`
	Resolved  map[string]uint `json:"resolved"`
	Ports     map[uint16]uint `json:"ports"`
	Count     int             `json:"count"`
}

type FileStats struct {
	LastAccessed           *datastructs.RingSet `json:"last-accessed"`
	CountFilesCreated      int64                `json:"file-create-count"`
	CountFilesCreatedByExt map[string]int64     `json:"file-create-count-by-ext"`
	TimeFirstFileCreated   time.Time            `json:"first-file-create"`
	TimeLastFileCreated    time.Time            `json:"last-file-create"`
	CountFilesDeleted      int64                `json:"file-delete-count"`
	CountFilesDeletedByExt map[string]int64     `json:"file-delete-count-by-ext"`
	TimeFirstFileDeleted   time.Time            `json:"first-file-delete"`
	TimeLastFileDeleted    time.Time            `json:"last-file-delete"`
}

type ProcStats struct {
	CreateProcessCount int64               `json:"create-process-count"`
	Connections        map[string]*ConStat `json:"connections"`
	Files              FileStats           `json:"files"`
}

func NewProcStats() ProcStats {
	return ProcStats{
		Connections: make(map[string]*ConStat),
		Files: FileStats{
			LastAccessed:           datastructs.NewRingSet(50),
			CountFilesCreatedByExt: make(map[string]int64),
			CountFilesDeletedByExt: make(map[string]int64),
		},
	}
}

func (p *ProcStats) UpdateNetResolve(timestamp, ip, qname string) {
	cs := p.ConStat(ip)
	if cs.FirstSeen == "" {
		cs.FirstSeen = timestamp
	}
	cs.LastSeen = timestamp
	cs.Resolved[qname]++
}

func (p *ProcStats) UpdateCon(timestamp, ip string, port uint16) {
	cs := p.ConStat(ip)
	if cs.FirstSeen == "" {
		cs.FirstSeen = timestamp
	}
	cs.LastSeen = timestamp
	cs.Ports[port]++
	cs.Count++
}

func (p *ProcStats) ConStat(ip string) *ConStat {
	if _, ok := p.Connections[ip]; !ok {
		p.Connections[ip] = &ConStat{Resolved: make(map[string]uint), Ports: make(map[uint16]uint)}
	}
	return p.Connections[ip]
}

type ThreatScore struct {
	Signatures map[string]uint `json:"signatures"`
	Score      int64           `json:"score"`
}

func NewGeneScore() ThreatScore {
	return ThreatScore{make(map[string]uint), 0}
}

func (g *ThreatScore) Update(d *engine.Detection) {
	if d != nil {
		for _, s := range d.Signature.List() {
			g.Signatures[s.(string)]++
		}
		g.Score += int64(d.Criticality)
	}
}

func sysmonHashesToMap(hashes string) map[string]string {
	m := make(map[string]string)
	for _, h := range strings.Split(hashes, ",") {
		i := strings.Index(h, "=")
		if i+1 < len(h) {
			v := strings.ToLower(h[i+1:])

			// it is sha1
			if len(v) == 40 {
				m["sha1"] = v
				continue
			}

			// it is sha256
			if len(v) == 64 {
				m["sha256"] = v
			}

			// md5 or imphash
			if len(v) == 32 {
				switch {
				case strings.HasPrefix(h, "MD5="):
					m["md5"] = v
				case strings.HasPrefix(h, "IMPHASH="):
					m["imphash"] = v
				}
			}
		}
	}
	return m
}

type ProcessTrack struct {
	/* Private */
	hashes string

	/* Public */
	Image                  string            `json:"image"`
	ParentImage            string            `json:"parent-image"`
	PID                    int64             `json:"pid"`
	CommandLine            string            `json:"command-line"`
	ParentCommandLine      string            `json:"parent-command-line"`
	CurrentDirectory       string            `json:"cwd"`
	ParentCurrentDirectory string            `json:"parent-cwd"`
	ProcessGUID            string            `json:"process-guid"`
	User                   string            `json:"user"`
	ParentUser             string            `json:"parent-user"`
	IntegrityLevel         string            `json:"integrity-lvl"`
	ParentIntegrityLevel   string            `json:"parent-integrity-lvl"`
	ParentProcessGUID      string            `json:"parent-process-guid"`
	Services               string            `json:"services"`
	ParentServices         string            `json:"parent-services"`
	HashesMap              map[string]string `json:"hashes"`
	Signature              string            `json:"signature"`
	SignatureStatus        string            `json:"signature-status"`
	Signed                 bool              `json:"signed"`
	Ancestors              []string          `json:"ancestors"`
	Modules                []*ModuleInfo     `json:"modules"`
	Integrity              float64           `json:"integrity"`
	IntegrityTimeout       bool              `json:"integrity-timeout"`
	MemDumped              bool              `json:"memory-dumped"`
	DumpCount              int               `json:"dump-count"`
	ChildCount             int               `json:"child-count"` // number of currently running child proceses
	Stats                  ProcStats         `json:"statistics"`
	ThreatScore            ThreatScore       `json:"threat-score"`
	Terminated             bool              `json:"terminated"`
	TimeTerminated         time.Time         `json:"time-terminated"`
}

// NewProcessTrack creates a new processTrack structure enforcing
// that minimal information is encoded (image, guid, pid)
func NewProcessTrack(image, pguid, guid string, pid int64) *ProcessTrack {
	return &ProcessTrack{
		Image:             image,
		ParentProcessGUID: pguid,
		ProcessGUID:       guid,
		PID:               pid,
		Signature:         "?",
		SignatureStatus:   "?",
		Ancestors:         make([]string, 0),
		Modules:           make([]*ModuleInfo, 0),
		Integrity:         -1.0,
		Stats:             NewProcStats(),
		ThreatScore:       NewGeneScore(),
	}
}

func (t *ProcessTrack) SetHashes(hashes string) {
	t.hashes = hashes
	t.HashesMap = sysmonHashesToMap(hashes)
}

func (t *ProcessTrack) TerminateProcess() error {
	if !t.Terminated {
		return terminate(int(t.PID))
	}
	return nil
}

type ModuleInfo struct {
	hashes           string
	Image            string            `json:"image"`
	FileVersion      string            `json:"file-version"`
	Description      string            `json:"description"`
	Product          string            `json:"product"`
	Company          string            `json:"company"`
	OriginalFileName string            `json:"orginal-filename"`
	Hashes           map[string]string `json:"hashes"`
	Signature        string            `json:"signature"`
	SignatureStatus  string            `json:"signature-status"`
	Signed           bool              `json:"signed"`
	// Statistics
	LoadCount int64     `json:"load-count"`
	FirstLoad time.Time `json:"first-load"`
	LastLoad  time.Time `json:"last-load"`
}

func ModuleInfoFromEvent(e *event.EdrEvent) (i *ModuleInfo) {
	var ok bool

	i = &ModuleInfo{}
	i.Image, _ = e.GetStringOr(pathSysmonImageLoaded, "?")
	i.FileVersion, _ = e.GetStringOr(pathSysmonFileVersion, "?")
	i.Description, _ = e.GetStringOr(pathSysmonDescription, "?")
	i.Product, _ = e.GetStringOr(pathSysmonProduct, "?")
	i.Company, _ = e.GetStringOr(pathSysmonCompany, "?")
	i.OriginalFileName, _ = e.GetStringOr(pathSysmonOriginalFileName, "?")
	if i.hashes, ok = e.GetString(pathSysmonHashes); ok {
		i.Hashes = sysmonHashesToMap(i.hashes)
	}
	i.Signature, _ = e.GetStringOr(pathSysmonSignature, "?")
	i.SignatureStatus, _ = e.GetStringOr(pathSysmonSignatureStatus, "?")
	i.Signed, _ = e.GetBool(pathSysmonSigned)
	i.LoadCount = 1
	i.FirstLoad = e.Timestamp()
	i.LastLoad = e.Timestamp()
	return
}

func (i *ModuleInfo) Id() string {
	return i.hashes
}

func (i *ModuleInfo) UpdateStatistics(other *ModuleInfo) {
	i.LastLoad = other.LastLoad
	i.LoadCount++
}

type DriverInfo struct {
	/* Private */
	hashes string

	/* Public */
	Image           string            `json:"image"`
	HashesMap       map[string]string `json:"hashes"`
	Signed          bool              `json:"signed"`
	Signature       string            `json:"signature"`
	SignatureStatus string            `json:"signature-status"`
}

func DriverInfoFromEvent(e *event.EdrEvent) (i *DriverInfo) {
	var ok bool

	i = &DriverInfo{}

	i.Image, _ = e.GetStringOr(pathSysmonImageLoaded, "?")
	if i.hashes, ok = e.GetString(pathSysmonHashes); ok {
		i.HashesMap = sysmonHashesToMap(i.hashes)
	}
	i.Signature, _ = e.GetStringOr(pathSysmonSignature, "?")
	i.SignatureStatus, _ = e.GetStringOr(pathSysmonSignatureStatus, "?")
	i.Signed, _ = e.GetBool(pathSysmonSigned)

	return
}

type ActivityTracker struct {
	sync.RWMutex
	// to store process track by parent process GUID
	//pguids      map[string]int
	guids map[string]*ProcessTrack
	// PIDs can be re-used so we have to jungle with two data structures
	rpids       map[int64]*ProcessTrack // for running processes
	tpids       map[int64]*ProcessTrack // for terminated processes
	blacklisted *datastructs.SyncedSet
	free        *datastructs.Fifo
	// modules loaded
	modules map[string]*ModuleInfo
	// driver loaded
	Drivers []DriverInfo
}

func NewActivityTracker() *ActivityTracker {
	pt := &ActivityTracker{
		//pguids:      make(map[string]int),
		guids:       make(map[string]*ProcessTrack),
		rpids:       make(map[int64]*ProcessTrack),
		tpids:       make(map[int64]*ProcessTrack),
		blacklisted: datastructs.NewSyncedSet(),
		free:        &datastructs.Fifo{},
		Drivers:     make([]DriverInfo, 0),
		modules:     make(map[string]*ModuleInfo),
	}
	// startup the routine to free resources
	pt.freeRtn()
	return pt
}

func (pt *ActivityTracker) delete(t *ProcessTrack) {
	pt.Lock()
	defer pt.Unlock()

	if t := pt.guids[t.ParentProcessGUID]; t != nil {
		t.ChildCount--
	}

	delete(pt.guids, t.ProcessGUID)
	// delete from terminated processes
	delete(pt.tpids, t.PID)
}

func (pt *ActivityTracker) freeRtn() {
	go func() {
		for {
			for e := pt.free.Pop(); e != nil; e = pt.free.Pop() {
				t := e.Value.(*ProcessTrack)
				now := time.Now()
				// delete the track only after some time because some
				// events come after process terminate events and we don't
				// want to miss correlation
				timeToDel := t.TimeTerminated.Add(time.Second * 10)
				if timeToDel.After(now) {
					delta := timeToDel.Sub(now)
					time.Sleep(delta)
				}
				// we don't free the process structure if it still has a child
				// this is mostly to keep track of parent processes when generating
				// a report
				if t.ChildCount > 0 {
					pt.free.Push(t)
					// we need to sleep there because we
					// can end up reprocessing the same
					// track over and over
					time.Sleep(1 * time.Second)
					continue
				}
				// delete ProcessTrack from ProcessTracker
				pt.delete(t)
			}
			// we have to wait here not to go in an
			// empty endless loop (if nothing in free list)
			time.Sleep(1 * time.Second)
		}
	}()
}

// returns true if DumpCount member of processTrack is below max argument
// and increments if necessary. This function is used to check whether we
// should still dump information given a guid
func (pt *ActivityTracker) CheckDumpCountOrInc(guid string, max int, deflt bool) bool {
	pt.Lock()
	defer pt.Unlock()
	if track, ok := pt.guids[guid]; ok {
		if track.DumpCount < max {
			track.DumpCount++
			return true
		}
		return false
	}
	// we return a parametrized default value (cleaner than returning global)
	return deflt
}

func (pt *ActivityTracker) Add(t *ProcessTrack) {
	pt.Lock()
	defer pt.Unlock()
	//pt.pguids[t.ParentProcessGUID]++
	if t := pt.guids[t.ParentProcessGUID]; t != nil {
		t.ChildCount++
	}
	pt.guids[t.ProcessGUID] = t
	pt.rpids[t.PID] = t
}

func (pt *ActivityTracker) PS() map[string]ProcessTrack {
	pt.RLock()
	defer pt.RUnlock()
	ps := make(map[string]ProcessTrack)
	for guid, t := range pt.guids {
		t.HashesMap = sysmonHashesToMap(t.hashes)
		ps[guid] = *t
	}
	return ps
}

func (pt *ActivityTracker) Blacklist(cmdLine string) {
	pt.blacklisted.Add(cmdLine)
}

func (pt *ActivityTracker) IsBlacklisted(cmdLine string) bool {
	return pt.blacklisted.Contains(cmdLine)
}

func (pt *ActivityTracker) GetParentByGuid(guid string) *ProcessTrack {
	pt.RLock()
	defer pt.RUnlock()
	if c, ok := pt.guids[guid]; ok {
		return pt.guids[c.ParentProcessGUID]
	}
	return nil
}

func (pt *ActivityTracker) GetByGuid(guid string) *ProcessTrack {
	pt.RLock()
	defer pt.RUnlock()
	return pt.guids[guid]
}

func (pt *ActivityTracker) GetByPID(pid int64) *ProcessTrack {
	pt.RLock()
	defer pt.RUnlock()
	// if we find processes in running processes
	if t := pt.rpids[pid]; t != nil {
		return t
	}
	// if we find process in terminated processes
	return pt.tpids[pid]
}

func (pt *ActivityTracker) ContainsGuid(guid string) bool {
	pt.RLock()
	defer pt.RUnlock()
	_, ok := pt.guids[guid]
	return ok
}

func (pt *ActivityTracker) ContainsPID(pid int64) bool {
	pt.RLock()
	defer pt.RUnlock()
	_, ok := pt.rpids[pid]
	return ok
}

func (pt *ActivityTracker) Modules() (s []ModuleInfo) {
	s = make([]ModuleInfo, 0)
	for _, m := range pt.modules {
		s = append(s, *m)
	}
	return
}

// GetModuleOrUpdate retrieves an already existing ModuleInfo or updates
// the map of known ModuleInfo and returns the ModuleInfo updated
func (pt *ActivityTracker) GetModuleOrUpdate(i *ModuleInfo) *ModuleInfo {
	pt.Lock()
	defer pt.Unlock()
	if old, ok := pt.modules[i.Id()]; ok {
		old.UpdateStatistics(i)
		return old
	}
	pt.modules[i.Id()] = i
	return i
}

func (pt *ActivityTracker) IsTerminated(guid string) bool {
	if t := pt.GetByGuid(guid); t != nil {
		return t.Terminated
	}
	return true
}

func (pt *ActivityTracker) Terminate(guid string) error {
	if t := pt.GetByGuid(guid); t != nil {
		t.Terminated = true
		t.TimeTerminated = time.Now()
		// PID entry must be cleared as soon as possible
		// to avoid issues like deleting a re-used PID in delete method
		delete(pt.rpids, t.PID)
		// we put it in the map of terminated processes
		pt.tpids[t.PID] = t
		pt.free.Push(t)
	}
	return nil
}
