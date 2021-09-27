package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/whids/event"
)

type RawEvent struct {
	Timestamp time.Time
	data      []byte
}

func NewRawEvent(e *event.EdrEvent) (r *RawEvent, err error) {
	r = &RawEvent{}
	r.Timestamp = e.Timestamp()
	r.data, err = json.Marshal(e)
	return
}

func DecodeRawEvent(b []byte) (r *RawEvent, err error) {
	var i int
	var intTS int64

	r = &RawEvent{}
	if i = bytes.Index(b, []byte(":")); i != -1 {
		if intTS, err = strconv.ParseInt(string(b[:i]), 10, 64); err != nil {
			return
		}
		r.Timestamp = time.Unix(0, intTS)
	}
	s := b[i+1:]
	r.data = make([]byte, len(s))
	copy(r.data, s)
	return
}

func (e *RawEvent) Less(other datastructs.Sortable) bool {
	return e.Timestamp.Before(other.(*RawEvent).Timestamp)
}

func (e *RawEvent) Encode() []byte {
	header := fmt.Sprintf("%d:", e.Timestamp.UTC().UnixNano())
	b := make([]byte, 0, len(e.data)+len(header))
	b = append(b, []byte(header)...)
	b = append(b, e.data...)
	return b
}

func (e *RawEvent) Event() (evt *event.EdrEvent, err error) {
	evt = &event.EdrEvent{}
	err = json.Unmarshal(e.data, &evt)
	return
}
