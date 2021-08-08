package api

import (
	"math/rand"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/datastructs"
)

type LogStream struct {
	closed bool
	S      chan evtx.GoEvtxMap
}

func (s *LogStream) Stream(e evtx.GoEvtxMap) bool {
	for {
		if s.closed {
			close(s.S)
			return false
		}
		select {
		case s.S <- e:
			return true
		default:
			time.Sleep(time.Millisecond * 10)
		}
	}
}

func (s *LogStream) Close() {
	s.closed = true
}

type EventStreamer struct {
	sync.RWMutex
	queue   datastructs.Fifo
	streams map[int]*LogStream
}

func NewEventStreamer() *EventStreamer {
	return &EventStreamer{
		queue:   datastructs.Fifo{},
		streams: map[int]*LogStream{},
	}
}

func (s *EventStreamer) NewStream() *LogStream {
	s.Lock()
	defer s.Unlock()
	ls := &LogStream{S: make(chan evtx.GoEvtxMap)}
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

func (s *EventStreamer) Queue(e evtx.GoEvtxMap) {
	s.Lock()
	defer s.Unlock()
	// we queue only if there is at least a stream open
	if len(s.streams) > 0 {
		s.queue.Push(e)
	}
}

func (s *EventStreamer) Stream() {
	go func() {
		for {
			if i := s.queue.Pop(); i != nil {
				e := i.Value.(evtx.GoEvtxMap)
				for id, stream := range s.streams {
					if ok := stream.Stream(e); !ok {
						s.delStream(id)
					}
				}
			} else {
				// we sleep only if there is nothing to stream
				// to minimize delay
				time.Sleep(time.Millisecond * 50)
			}
		}
	}()
}

func (s *EventStreamer) delStream(id int) {
	s.Lock()
	defer s.Unlock()
	delete(s.streams, id)
}

func (s *EventStreamer) Close() {

}
