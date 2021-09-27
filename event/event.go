package event

import (
	"fmt"
	"strconv"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/whids/utils"
)

var (
	eventDataPath = engine.Path("/Event/EventData")
	userDataPath  = engine.Path("/Event/UserData")
)

type EdrData struct {
	Endpoint struct {
		UUID     string
		IP       string
		Hostname string
		Group    string
	}
	Event struct {
		Hash        string
		Detection   bool
		ReceiptTime time.Time
	}
}

type InnerEvent struct {
	*etw.Event
	EdrData   *EdrData          `json:",omitempty"`
	Detection *engine.Detection `json:",omitempty"`
}

type EdrEvent struct {
	Event InnerEvent
}

func NewEdrEvent(e *etw.Event) *EdrEvent {
	return &EdrEvent{InnerEvent{e, nil, nil}}
}

func (e *EdrEvent) InitEdrData() {
	e.Event.EdrData = &EdrData{}
}

func (e *EdrEvent) Hash() string {
	tmp := *e
	// null out EdrData as it does not come into hash calculation
	tmp.Event.EdrData = nil
	return utils.HashEventBytes(utils.Json(tmp))
}

func (e *EdrEvent) GetStringOr(p engine.XPath, or string) (s string, ok bool) {
	if s, ok = e.GetString(p); ok {
		return
	}
	return or, ok
}

func (e *EdrEvent) GetString(p engine.XPath) (s string, ok bool) {
	var i interface{}

	if i, ok = e.Get(p); ok {
		s, ok = i.(string)
		return
	}

	return
}

func (e *EdrEvent) GetInt(p engine.XPath) (i int64, ok bool) {
	var s string
	var err error

	if s, ok = e.GetString(p); ok {
		if i, err = strconv.ParseInt(s, 0, 64); err == nil {
			return
		}
	}

	return
}

func (e *EdrEvent) GetBool(p engine.XPath) (b bool, ok bool) {
	var s string
	var err error

	if s, ok = e.GetString(p); ok {
		if b, err = strconv.ParseBool(s); err == nil {
			return
		}
	}

	return
}

func (e *EdrEvent) Set(p engine.XPath, i interface{}) (err error) {
	switch {
	case p.StartsWith(eventDataPath):
		e.Event.EventData[p.Last()] = i
		return
	case p.StartsWith(userDataPath):
		e.Event.UserData[p.Last()] = i
		return
	}
	return fmt.Errorf("unknown path: %s", p)
}

func (e *EdrEvent) SetDetection(d *engine.Detection) {
	// we make the choice not to set detection when it is empty
	if d.Criticality > 0 || d.Signature.Len() > 0 || d.Actions.Len() > 0 || len(d.ATTACK) > 0 {
		e.Event.Detection = d
	}
}

func (e *EdrEvent) Get(p engine.XPath) (i interface{}, ok bool) {
	switch {
	case p.StartsWith(eventDataPath):
		i, ok = e.Event.EventData[p.Last()]
		return
	case p.StartsWith(userDataPath):
		i, ok = e.Event.UserData[p.Last()]
		return
	}
	return nil, false
}

func (e *EdrEvent) IsDetection() bool {
	if e.Event.Detection != nil {
		return e.Event.Detection.IsAlert()
	}
	return false
}

func (e *EdrEvent) GetDetection() *engine.Detection {
	return e.Event.Detection
}

func (e *EdrEvent) Channel() string {
	return e.Event.System.Channel
}

func (e *EdrEvent) Computer() string {
	return e.Event.System.Computer
}

func (e *EdrEvent) EventID() int64 {
	return int64(e.Event.System.EventID)
}

func (e *EdrEvent) Timestamp() time.Time {
	return e.Event.System.TimeCreated.SystemTime
}

func (er *EdrEvent) Copy() (new *EdrEvent) {
	etwEvent := *er.Event.Event
	new = NewEdrEvent(&etwEvent)
	new.Event.EdrData = er.Event.EdrData
	new.Event.Detection = er.Event.Detection
	return
}
