package api

import (
	"math/rand"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/whids/event"
)

type LogStream struct {
	closed bool
	queue  datastructs.Fifo
	S      chan *event.EdrEvent
}

func (s *LogStream) Queue(e *event.EdrEvent) bool {
	if s.closed {
		return false
	}
	s.queue.Push(e)
	return true
}

func (s *LogStream) Stream() {
	go func() {
		defer close(s.S)
		for !s.closed {
			if i := s.queue.Pop(); i != nil {
				e := i.Value.(*event.EdrEvent)
				s.S <- e
			} else {
				time.Sleep(time.Millisecond * 50)
			}
		}
	}()
}

func (s *LogStream) Close() {
	s.closed = true
}

type EventStreamer struct {
	sync.RWMutex
	streams map[int]*LogStream
}

func NewEventStreamer() *EventStreamer {
	return &EventStreamer{
		streams: map[int]*LogStream{},
	}
}

func (s *EventStreamer) NewStream() *LogStream {
	s.Lock()
	defer s.Unlock()
	ls := &LogStream{S: make(chan *event.EdrEvent), queue: datastructs.Fifo{}}
	s.streams[s.newId()] = ls
	return ls
}

func (s *EventStreamer) newId() int {
	var id int
	for {
		id = rand.Int()
		if _, ok := s.streams[id]; !ok {
			return id
		}
	}
}

func (s *EventStreamer) Queue(e *event.EdrEvent) {
	s.Lock()
	defer s.Unlock()
	// we queue only if there is at least a stream open
	if len(s.streams) > 0 {
		for id, stream := range s.streams {
			if ok := stream.Queue(e); !ok {
				delete(s.streams, id)
			}
		}
	}
}
