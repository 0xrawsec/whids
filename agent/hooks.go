package agent

import (
	"reflect"
	"runtime"
	"sync"

	"github.com/0xrawsec/whids/event"
)

// Hook structure definition
// hooking functions are supposed to run quickly since it is
// run synchronously with the Gene scanner. Likewise, the
// hooking functions should never panic the program.
type Hook func(*Agent, *event.EdrEvent)

type eventMap map[int64][]Hook

type hookCache struct {
	c map[string]eventMap
}

func newHookCache() *hookCache {
	return &hookCache{
		c: make(map[string]eventMap),
	}
}

func (h hookCache) get(e *event.EdrEvent) (hooks []Hook, ok bool) {
	var eventIdsMap eventMap

	if eventIdsMap, ok = h.c[e.Channel()]; !ok {
		return
	}

	hooks, ok = eventIdsMap[e.EventID()]
	return
}

func (h hookCache) cache(hk Hook, e *event.EdrEvent) {
	// create eventMap if necessary
	if _, ok := h.c[e.Channel()]; !ok {
		h.c[e.Channel()] = make(eventMap)
	}

	// create Hook slice if necessary
	em := h.c[e.Channel()]
	if _, ok := em[e.EventID()]; !ok {
		em[e.EventID()] = make([]Hook, 0, 1)
	}

	// append the hook to the list of hooks
	if hk != nil {
		em[e.EventID()] = append(em[e.EventID()], hk)
	}
}

// HookManager structure definition to easier handle hooks
type HookManager struct {
	sync.RWMutex
	Filters []*Filter
	Hooks   []Hook
	cache   *hookCache
}

// NewHookMan creates a new HookManager structure
func NewHookMan() *HookManager {
	return &HookManager{Filters: make([]*Filter, 0),
		Hooks: make([]Hook, 0),
		cache: newHookCache(),
	}
}

// Hook register a hook for a given filter
func (hm *HookManager) Hook(h Hook, f *Filter) {
	hm.Lock()
	defer hm.Unlock()

	hm.Hooks = append(hm.Hooks, h)
	hm.Filters = append(hm.Filters, f)
}

// RunHooksOn runs the hook on a given event
func (hm *HookManager) RunHooksOn(h *Agent, e *event.EdrEvent) (ret bool) {
	var ok bool
	var hooks []Hook

	hm.Lock()
	defer hm.Unlock()

	// Don't waste resources if nothing to do
	if len(hm.Filters) == 0 {
		return
	}

	// We have to check all the filters if we don't know yet
	// which hooks should apply on this kind of event
	if hooks, ok = hm.cache.get(e); !ok {
		// we create an empty slice for e in order to return
		// cache hooks for events with no filters
		hm.cache.cache(nil, e)
		// we go through all the filters
		for i, f := range hm.Filters {
			if f.Match(e) {
				hm.cache.cache(hm.Hooks[i], e)
			}
		}
		// we update the list of hooks to apply
		hooks, _ = hm.cache.get(e)
	}

	for _, hook := range hooks {
		// debug hooks
		//log.Infof("Running hook: %s", getFunctionName(hook))
		hook(h, e)
		// We set return value to true if a hook has been applied
		ret = true
	}

	return
}

func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
