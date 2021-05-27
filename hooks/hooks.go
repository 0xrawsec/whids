package hooks

import (
	"fmt"
	"sync"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/datastructs"
)

type FilterDefinition struct {
	EventIDs []int
	Channel  string
}

// Filter structure
type Filter struct {
	EventIDs datastructs.SyncedSet
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
func (f *Filter) Match(e *evtx.GoEvtxMap) bool {
	if !f.EventIDs.Contains(e.EventID()) && f.EventIDs.Len() > 0 {
		return false
	}
	// Don't check channel if empty string
	if f.Channel != "" && f.Channel != e.Channel() {
		return false
	}
	return true
}

// Hook structure definition
// hooking functions are supposed to run quickly since it is
// run synchronously with the Gene scanner. Likewise, the
// hooking functions should never panic the program.
type Hook func(*evtx.GoEvtxMap)

// HookManager structure definition to easier handle hooks
type HookManager struct {
	sync.RWMutex
	Filters []*Filter
	Hooks   []Hook
	memory  map[string][]int // used to memorize hooks given a couple of (channel, eventid)
}

// NewHookMan creates a new HookManager structure
func NewHookMan() *HookManager {
	return &HookManager{Filters: make([]*Filter, 0),
		Hooks:  make([]Hook, 0),
		memory: make(map[string][]int)}
}

// Hook register a hook for a given filter
func (hm *HookManager) Hook(h Hook, f *Filter) {
	hm.Hooks = append(hm.Hooks, h)
	hm.Filters = append(hm.Filters, f)
}

func eventIdentifier(e *evtx.GoEvtxMap) string {
	return fmt.Sprintf("%s:%d", e.Channel(), e.EventID())
}

// RunHooksOn runs the hook on a given event
func (hm *HookManager) RunHooksOn(e *evtx.GoEvtxMap) (ret bool) {
	// Don't waste resources if nothing to do
	if len(hm.Filters) == 0 {
		return
	}

	key := eventIdentifier(e)
	// We have to check all the filters if we don't know yet
	// which hooks should apply on this kind of event
	hm.Lock()
	if _, ok := hm.memory[key]; !ok {
		for i, f := range hm.Filters {
			if f.Match(e) {
				if _, ok := hm.memory[key]; !ok {
					hm.memory[key] = make([]int, 0)
				}
				hm.memory[key] = append(hm.memory[key], i)
			}
		}
	}
	hm.Unlock()
	hm.RLock()
	// hi: hook index
	for _, hi := range hm.memory[key] {
		hook := hm.Hooks[hi]
		hook(e)
		// We set return value to true if a hook has been applied
		ret = true
	}
	hm.RUnlock()
	return
}
