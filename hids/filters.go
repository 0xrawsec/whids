package hids

import (
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/whids/event"
)

//Sysmon related
var (
	// sysmonChannel Sysmon windows event log channel
	sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

	// Filters definitions
	fltAnyEvent = NewFilter([]int64{}, "")

	// Sysmon filters
	fltAnySysmon       = NewFilter([]int64{}, sysmonChannel)
	fltProcessCreate   = NewFilter([]int64{SysmonProcessCreate}, sysmonChannel)
	fltTrack           = NewFilter([]int64{SysmonProcessCreate, SysmonDriverLoad}, sysmonChannel)
	fltProcTermination = NewFilter([]int64{SysmonProcessTerminate}, sysmonChannel)
	fltImageLoad       = NewFilter([]int64{SysmonImageLoad}, sysmonChannel)
	fltRegSetValue     = NewFilter([]int64{SysmonRegSetValue}, sysmonChannel)
	//fltNetwork         = NewFilter([]int64{SysmonNetworkConnect, SysmonDNSQuery}, sysmonChannel)
	//fltDNS             = NewFilter([]int64{SysmonDNSQuery}, sysmonChannel)
	fltClipboard      = NewFilter([]int64{SysmonClipboardChange}, sysmonChannel)
	fltImageTampering = NewFilter([]int64{SysmonProcessTampering}, sysmonChannel)

	fltImageSize = NewFilter([]int64{
		SysmonProcessCreate,
		SysmonDriverLoad,
		SysmonImageLoad},
		sysmonChannel)

	fltStats = NewFilter([]int64{
		SysmonProcessCreate,
		SysmonNetworkConnect,
		SysmonFileCreate,
		SysmonDNSQuery,
		SysmonFileDelete,
		SysmonFileDeleteDetected},
		sysmonChannel)
)

// Security channel related
var (
	// securityChannel Security windows event log channel
	securityChannel = "Security"
	// Security filters
	fltFSObjectAccess = NewFilter([]int64{SecurityAccessObject}, securityChannel)
)

// ETW Kernel File related
var (
	kernelFileChannel = "Microsoft-Windows-Kernel-File/Analytic"
	/*fltKernelFile     = NewFilter([]int64{
	KernelFileCreate,
	KernelFileClose,
	KernelFileRead,
	KernelFileWrite},
	kernelFileChannel)
	*/
	fltKernelFile = NewFilter([]int64{},
		kernelFileChannel)
)

// Filter structure
type Filter struct {
	EventIDs *datastructs.SyncedSet
	Channel  string
}

// NewFilter creates a new Filter structure
func NewFilter(eids []int64, channel string) *Filter {
	f := &Filter{}
	f.EventIDs = datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(eids)...)
	f.Channel = channel
	return f
}

// Match checks if an event matches the filter
func (f *Filter) Match(e *event.EdrEvent) bool {
	if !f.EventIDs.Contains(e.EventID()) && f.EventIDs.Len() > 0 {
		return false
	}
	// Don't check channel if empty string
	if f.Channel != "" && f.Channel != e.Channel() {
		return false
	}
	return true
}
