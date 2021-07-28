package logger

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/whids/utils"
)

const (
	// IndexExt is the file extension used for index files
	IndexExt = ".index"
	// IndexedLogfileExt is the file extension used by logfiles
	IndexedLogfileExt = ".gz"

	// DefaultLogPerm default logfile permission for Manager
	DefaultLogPerm = 0600

	tGranularity = time.Hour
)

var (
	TimeFormat  = time.RFC3339Nano
	IndexHeader = "Start,Stop,Offset,EventCount"
)

func stdTime(t time.Time) time.Time {
	return t.UTC()
}

func timestampToDir(t time.Time) string {
	t = stdTime(t)
	return filepath.Join(t.Format("20060102"), t.Format("15"))
}

func fmtTime(t time.Time) string {
	return stdTime(t).Format(TimeFormat)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(TimeFormat, s)
}

// TransactionId type to identify a logging session
type TransactionId uint64

// EventLogger structure used to log EDR events
type EventLogger struct {
	sync.RWMutex
	root        string
	base        string
	maxSize     int64
	cache       map[string]*IndexedLogfile
	transacting TransactionId
}

// NewEventLogger creates a new EventLogger
func NewEventLogger(root, base string, size int64) *EventLogger {
	root = strings.TrimRight(root, string(os.PathSeparator))
	return &EventLogger{
		root:    root,
		base:    base,
		maxSize: size,
		cache:   make(map[string]*IndexedLogfile),
	}
}

func (l *EventLogger) openLogfile(t time.Time, key string) (il *IndexedLogfile, err error) {
	var ok, rotate bool
	var stat os.FileInfo

	// key must not be empty
	if key == "" {
		err = fmt.Errorf("key must not be empty")
		return
	}

	dir := filepath.Join(l.root, key, timestampToDir(t))
	path := filepath.Join(dir, l.base)

	if stat, err = os.Stat(path); err == nil && stat.Mode().IsRegular() {
		if stat.Size() > l.maxSize {
			rotate = true
		}
	}

	// the file is already opened
	if il, ok = l.cache[path]; ok && !rotate {
		return
	} else if ok && rotate {
		il.Close()
		delete(l.cache, path)
	}

	if rotate {
		RenameIndexedLogfile(path, ArchiveFilename(path))
	}

	// we create output directory
	if err = os.MkdirAll(dir, utils.DefaultPerms); err != nil {
		return
	}

	il, err = OpenIndexedLogfile(path)
	l.cache[path] = il
	return
}

// InitTransaction initializes a new logging transaction
// only attempts to use WriteEvent with the proper id will succeed
func (l *EventLogger) InitTransaction() (id TransactionId) {
	l.Lock()

	for ; id == 0; id = TransactionId(rand.Uint64()) {
	}

	l.transacting = id
	return
}

// WriteEvent writes an event to an IndexedLogfile chosen according to
// the internal algorithm of the EventLogger
func (l *EventLogger) WriteEvent(id TransactionId, key string, evt *evtx.GoEvtxMap) (n int, err error) {
	var il *IndexedLogfile
	var re *RawEvent

	if l.transacting == id {
		if re, err = NewRawEvent(evt); err != nil {
			return
		}

		if il, err = l.openLogfile(re.Timestamp, key); err != nil {
			return 0, fmt.Errorf("failed to open logfile: %w", err)
		}

		return il.WriteRawEvent(re)

	}
	return 0, fmt.Errorf("invalid transaction id %d (expected: %d)", id, l.transacting)
}

// CountFiles returns the count of opened IndexedFiles
func (l *EventLogger) CountFiles() int {
	return len(l.cache)
}

func (l *EventLogger) endTransaction() {
	l.transacting = 0
}

// CommitTransaction commits a transaction leaving the place for a new one.
// A transaction needs to be committed before a new one can be initialized
// and used.
func (l *EventLogger) CommitTransaction() (lastErr error) {
	defer l.Unlock()
	l.endTransaction()
	return l.close()
}

func (l *EventLogger) close() (lastErr error) {
	for path, il := range l.cache {
		if err := il.Close(); err != nil {
			lastErr = err
		}
		delete(l.cache, path)
	}
	return
}

// Close closes an EventLogger
func (l *EventLogger) Close() (lastErr error) {
	l.Lock()
	l.endTransaction()
	defer l.Unlock()
	return l.close()
}
