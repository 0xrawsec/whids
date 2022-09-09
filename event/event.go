package event

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/whids/utils"
)

var (
	emptySha1 = strings.Repeat("0", crypto.SHA1.Size()*2)
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
	skip      bool
}

type EdrEvent struct {
	Event InnerEvent
}

func NewEdrEvent(e *etw.Event) *EdrEvent {
	return &EdrEvent{InnerEvent{Event: e}}
}

func (e *EdrEvent) InitEdrData() {
	e.Event.EdrData = &EdrData{}
}

func (e *EdrEvent) Hash() string {
	var b []byte
	var err error

	tmp := *e

	// null out EdrData as it does not come into hash calculation
	tmp.Event.EdrData = nil

	if b, err = utils.Json(tmp); err != nil {
		return emptySha1
	}

	return utils.Sha1EventBytes(b)
}

func (e *EdrEvent) GetStringOr(p *engine.XPath, or string) string {
	if s, ok := e.GetString(p); ok {
		return s
	}
	return or
}

func (e *EdrEvent) GetString(p *engine.XPath) (s string, ok bool) {
	var i interface{}

	if i, ok = e.Get(p); ok {
		s, ok = i.(string)
		return
	}

	return
}

func (e *EdrEvent) GetInt(p *engine.XPath) (i int64, ok bool) {
	var s string
	var err error

	if s, ok = e.GetString(p); ok {
		if i, err = strconv.ParseInt(s, 0, 64); err == nil {
			return
		}
	}
	return
}

func (e *EdrEvent) GetIntOr(p *engine.XPath, or int64) int64 {
	if i, ok := e.GetInt(p); ok {
		return i
	}
	return or
}

func (e *EdrEvent) GetUint(p *engine.XPath) (i uint64, ok bool) {
	var s string
	var err error

	if s, ok = e.GetString(p); ok {
		if i, err = strconv.ParseUint(s, 0, 64); err == nil {
			return
		}
	}
	return
}

func (e *EdrEvent) GetUintOr(p *engine.XPath, or uint64) uint64 {
	if u, ok := e.GetUint(p); ok {
		return u
	}
	return or
}

func (e *EdrEvent) GetBool(p *engine.XPath) (b bool, ok bool) {
	var s string
	var err error

	if s, ok = e.GetString(p); ok {
		if b, err = strconv.ParseBool(s); err == nil {
			return
		}
	}

	return
}

// SetIfOr set value if cond == true
func (e *EdrEvent) SetIf(p *engine.XPath, value interface{}, cond bool) (err error) {
	if cond {
		return e.Set(p, value)
	}
	return nil
}

// SetIfOr set value if cond == true or other
func (e *EdrEvent) SetIfOr(p *engine.XPath, value interface{}, cond bool, other interface{}) (err error) {
	if cond {
		return e.Set(p, value)
	}
	return e.Set(p, other)
}

func (e *EdrEvent) SetIfMissing(p *engine.XPath, i interface{}) (err error) {
	if _, ok := e.Get(p); ok {
		// nothing to do as the field already exists
		return
	}

	return e.Set(p, i)
}

func (e *EdrEvent) Set(p *engine.XPath, i interface{}) (err error) {
	switch {
	case p.Flags.EventDataField:
		e.Event.EventData[p.Last()] = i
		return
	case p.Flags.UserDataField:
		e.Event.UserData[p.Last()] = i
		return
	}
	return fmt.Errorf("unknown path: %s", p)
}

func (e *EdrEvent) SetDetection(d *engine.Detection) {
	if d != nil {
		// we make the choice not to set detection when it is empty
		if d.Criticality > 0 || len(d.ATTACK) > 0 {
			e.Event.Detection = d
			return
		}
		if d.Signature != nil {
			if d.Signature.Len() > 0 {
				e.Event.Detection = d
				return
			}
		}
		if d.Actions != nil {
			if d.Actions.Len() > 0 {
				e.Event.Detection = d
				return

			}
		}
	}
}

func (e *EdrEvent) Get(p *engine.XPath) (i interface{}, ok bool) {
	switch {
	case p.Flags.EventDataField:
		i, ok = e.Event.EventData[p.Last()]
		return
	case p.Flags.UserDataField:
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

// Skip mark the event to be skipped subsequent calls
// to IsSkipped will return true
func (e *EdrEvent) Skip() {
	e.Event.skip = true
}

// IsSkipped returns true if the event has been marked
// to be skipped
func (e *EdrEvent) IsSkipped() bool {
	return e.Event.skip
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
