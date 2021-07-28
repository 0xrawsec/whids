package logger

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
)

const (
	MaxOpenedLogfile = 1024
)

func reverseIndex(index *datastructs.SortedSlice) {
	s := index.Slice()
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

type chunk struct {
	start   time.Time
	stop    time.Time
	entries []*IndexEntry
}

func newChunk() *chunk {
	return &chunk{entries: make([]*IndexEntry, 0)}
}

func (c *chunk) add(e *IndexEntry) {
	if e.Start.Before(c.start) {
		c.start = e.Start
	}
	if e.Stop.After(c.stop) {
		c.stop = e.Stop
	}
	c.entries = append(c.entries, e)
}

func (c *chunk) overlaps(e *IndexEntry) bool {
	return (c.start.After(e.Start) && c.stop.Before(e.Stop)) || c.contains(e.Start) || c.contains(e.Stop) || (e.Start.After(c.start) && e.Stop.Before(c.stop))
}

// contains returns true if time is in between entry start and stop
func (c *chunk) contains(ts time.Time) bool {
	return (ts.After(c.start) && ts.Before(c.stop)) || c.start == ts || c.stop == ts
}

// EventSearcher is used to search for events accross the file system
type EventSearcher struct {
	sync.Mutex
	root  string
	cache map[string]*IndexedLogfile
	err   error
}

// NewEventSearcher creates a new EventSearcher structure to be used to search logs
func NewEventSearcher(root string) (s *EventSearcher) {
	return &EventSearcher{
		root:  root,
		cache: make(map[string]*IndexedLogfile),
	}
}

func (s *EventSearcher) keys() (keys []string, err error) {
	var des []fs.DirEntry
	if des, err = os.ReadDir(s.root); err != nil {
		return
	}
	keys = make([]string, 0, len(des))
	for _, de := range des {
		if fsutil.IsDir(filepath.Join(s.root, de.Name())) {
			keys = append(keys, de.Name())
		}
	}
	return
}

func (s *EventSearcher) buildIndex(start, stop time.Time, key string) (index *datastructs.SortedSlice, err error) {
	var ifd *IndexFile
	var keys []string

	start = stdTime(start)
	stop = stdTime(stop)
	index = datastructs.NewSortedSlice()
	marked := datastructs.NewSet()

	if key != "" {
		if keys, err = s.keys(); err != nil {
			return
		}
	} else {
		keys = []string{key}
	}

	// we add our tGranularity to stop to make sure we cover all events
	for t := start; t.Before(stop.Add(tGranularity)); t = t.Add(tGranularity) {
		for _, key := range keys {
			dir := filepath.Join(s.root, key, timestampToDir(t))
			if fsutil.IsDir(dir) {
				if !marked.Contains(dir) {
					for wi := range fswalker.Walk(dir) {
						for _, fi := range wi.Files {
							if strings.HasSuffix(fi.Name(), IndexExt) {
								path := filepath.Join(wi.Dirpath, fi.Name())
								// we continue if key is not in path
								if key != "" && !strings.Contains(path, key) {
									continue
								}
								// opening index file
								if ifd, err = OpenIndexFile(path); err != nil {
									return
								}
								// appending index entries
								for indexEntry, err := ifd.Next(); indexEntry != nil && err == nil; indexEntry, err = ifd.Next() {
									// we append to the index only if it is relevant to our search
									if indexEntry.Overlaps(start, stop) {
										index.Insert(indexEntry)
									}
								}
								// closing index file
								ifd.Close()
								if err != nil {
									return
								}
							}
						}
					}
					marked.Add(dir)
				}
			}
		}
	}
	reverseIndex(index)
	return
}

func (s *EventSearcher) getFile(ie *IndexEntry) (il *IndexedLogfile, err error) {
	s.Lock()
	defer s.Unlock()

	var ok bool
	logPath := ie.indexFile.LogfilePath()

	if len(s.cache) > MaxOpenedLogfile {
		if err = s.close(); err != nil {
			err = fmt.Errorf("failed to close logfiles: %w", err)
			return
		}
	}

	if il, ok = s.cache[logPath]; !ok {
		if il, err = OpenIndexedLogfile(logPath); err != nil {
			err = fmt.Errorf("failed to open logfile from %s: %w", logPath, err)
			return
		}
		s.cache[logPath] = il
	}
	return
}

func (s *EventSearcher) readRawEvents(ie *IndexEntry) (events []*RawEvent, err error) {
	var il *IndexedLogfile

	logPath := ie.indexFile.LogfilePath()
	if il, err = s.getFile(ie); err != nil {
		return
	}

	events, err = il.ReadRawEvents(ie.Offset, ie.EventCount)
	if err != nil {
		err = fmt.Errorf("failed to read events from %s (index:%s): %w", logPath, ie.indexFile.path, err)
	}

	return
}

// Events returns a channel of RawEvents
func (s *EventSearcher) Events(start, stop time.Time, key string, count, skip int) (c chan *RawEvent) {
	var index *datastructs.SortedSlice
	c = make(chan *RawEvent)

	// times must always be UTC
	start = stdTime(start)
	stop = stdTime(stop)

	// if we fail at building the index
	if index, s.err = s.buildIndex(start, stop, key); s.err != nil {
		close(c)
		return
	}

	go func() {
		defer close(c)
		var err error
		var countEvents int
		var tmpEvents []*RawEvent

		sindex := index.Slice()
		// sindex is sorted with higher values first
		for i := 0; i < len(sindex) && countEvents < count; i++ {
			events := datastructs.NewSortedSlice()
			chunk := newChunk()

			for ; i < len(sindex); i++ {
				e := sindex[i].(*IndexEntry)
				chunk.add(e)
				if i == len(sindex)-1 {
					break
				}
				next := sindex[i+1].(*IndexEntry)
				if !chunk.overlaps(next) {
					break
				}
			}

			for _, ie := range chunk.entries {
				// we read events
				if tmpEvents, err = s.readRawEvents(ie); err != nil {
					s.err = err
					break
				}
				//for _, evt := range tmpEvents {
				for k := 0; k < len(tmpEvents) && countEvents < count; k++ {
					evt := tmpEvents[k]
					if skip > 0 {
						skip--
						continue
					}
					if (start.Before(evt.Timestamp) && stop.After(evt.Timestamp)) || evt.Timestamp == start || evt.Timestamp == stop {
						events.Insert(evt)
						countEvents++
					}
				}
			}

			for e := range events.ReversedIter() {
				c <- e.(*RawEvent)
			}
		}
	}()
	return
}

// Err returns any error which happened during a call to Events function
func (s *EventSearcher) Err() error {
	return s.err
}

func (s *EventSearcher) close() (lastErr error) {
	for p, il := range s.cache {
		if err := il.Close(); err != nil {
			lastErr = err
		}
		delete(s.cache, p)
	}
	return
}

// Close closes all the opened IndexedLogfile
func (s *EventSearcher) Close() (lastErr error) {
	s.Lock()
	defer s.Unlock()
	return s.close()
}
