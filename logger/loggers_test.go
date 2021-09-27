package logger

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
)

var (
	eventFile = "./data/events.json"
	events    = make([]event.EdrEvent, 0)
)

const (
	day   = time.Hour * 24
	month = day * 30
)

func init() {
	data, err := ioutil.ReadFile(eventFile)
	if err != nil {
		panic(err)
	}
	for line := range readers.Readlines(bytes.NewBuffer(data)) {
		event := event.EdrEvent{}
		json.Unmarshal(line, &event)
		events = append(events, event)
	}
}

func emitEvents(count int, random bool) (ce chan *event.EdrEvent) {
	ce = make(chan *event.EdrEvent)
	go func() {
		defer close(ce)
		for i := 0; i < count; i++ {
			i := rand.Int() % len(events)
			// we need to use a copy of the event as event
			// contains some pointer making shalow copy
			// copying that pointer too
			e := events[i].Copy()
			newTimestamp := time.Now()
			if random {
				delayMin := time.Duration(rand.Int()%120) * time.Minute
				if rand.Int()%2 == 0 {
					newTimestamp = newTimestamp.Add(-delayMin)
				} else {
					newTimestamp = newTimestamp.Add(delayMin)
				}
			}
			e.Event.System.TimeCreated.SystemTime = newTimestamp
			ce <- e
		}
	}()
	return
}

func timeSearch(t *testing.T, s *EventSearcher, start, stop time.Time, key string, count, skip int) (n int) {
	var prev *RawEvent
	var bytesR int
	timer := time.Now()
	for e := range s.Events(start, stop, key, count, skip) {
		// we control events are comming in good order
		if prev != nil {
			if prev.Timestamp.After(e.Timestamp) {
				t.Errorf("Events are not ordered: %s after %s", prev.Timestamp.UTC(), e.Timestamp.UTC())
			}
		}
		prev = e
		bytesR += len(e.data)
		n++
	}
	delta := time.Since(timer)
	t.Logf("")
	t.Logf("Time to read %d events: %s", count, delta)
	t.Logf("Read throughput: %.1f MB/s", float64(bytesR)/(utils.Mega*delta.Seconds()))
	t.Logf("Total size read: %d MB", bytesR/utils.Mega)
	if s.Err() != nil {
		t.Error(s.Err())
		t.FailNow()
	}
	return
}
func TestEventLogger(t *testing.T) {
	var nExpEvents int

	wg := sync.WaitGroup{}
	root := "data/logs"
	nroutines := 2000
	bytesR, bytesW := 0, 0
	key := "03e31275-2277-d8e0-bb5f-480fac7ee4ef"

	l := NewEventLogger(root, "logs.gz", utils.Mega*1)
	defer l.Close()
	os.RemoveAll("data/logs")
	start := time.Now()
	for i := 0; i < nroutines; i++ {
		wg.Add(1)
		// simulate concurrent writes
		nevents := rand.Int() % 100
		nExpEvents += nevents
		go func() {
			defer wg.Done()
			id := l.InitTransaction()
			for e := range emitEvents(nevents, false) {
				if n, err := l.WriteEvent(id, key, e); err != nil {
					t.Errorf("cannot write event: %s", err)
				} else {
					bytesW += n
				}
			}
			l.CommitTransaction()
			// attempts to write files out of a transaction
			for e := range emitEvents(10, false) {
				if _, err := l.WriteEvent(id, key, e); err == nil {
					t.Errorf("writing out of a transaction is not allowed")
				}
			}
		}()
	}
	wg.Wait()
	delta := time.Since(start)
	t.Logf("Time to write files: %s", delta)
	t.Logf("Total size written (uncompressed): %.1fMB", float64(bytesW)/utils.Mega)
	t.Logf("Write throughput: %.1fMB/s", float64(bytesW)/(utils.Mega*delta.Seconds()))

	if l.CountFiles() != 0 {
		t.Errorf("All files should be closed, %d files still opened", l.CountFiles())
	}

	now := time.Now()
	skip := rand.Int() % nExpEvents
	s := NewEventSearcher(root)
	defer s.Close()

	var prev *RawEvent
	count := 0
	timer := time.Now()
	for e := range s.Events(now.Add(-1*month), now.Add(1*month), key, nExpEvents, skip) {
		// compute size for throughput
		bytesR += len(e.data)

		if prev != nil {
			// we control events are comming in good order
			if prev.Timestamp.After(e.Timestamp) {
				t.Errorf("Events are not ordered: %s after %s", prev.Timestamp.UTC(), e.Timestamp.UTC())
			}
		}
		prev = e
		count++
	}

	delta = time.Since(timer)
	t.Logf("Time to read events: %s", time.Since(timer))
	t.Logf("Read throughput: %.1f MB/s", float64(bytesR)/(utils.Mega*delta.Seconds()))
	t.Logf("Total size read: %d MB", bytesR/utils.Mega)

	if s.Err() != nil {
		t.Error(s.Err())
		t.FailNow()
	}

	if count != nExpEvents-skip {
		t.Errorf("(written) %d != %d (read)", nExpEvents, count)
	}

	t.Logf("Events read: %d", count)

	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 100000, 1000)
	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 50000, 1000)
	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 10000, 10000)
	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 1000, 1000)
}
