package logger

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/whids/utils"
)

// RenameIndexedLogfile renames both an IndexLogfile and its associated IndexFile
func RenameIndexedLogfile(old, new string) (lastErr error) {
	if err := os.Rename(old, new); err != nil {
		lastErr = err
	}
	if err := os.Rename(IndexFileFromPath(old), IndexFileFromPath(new)); err != nil {
		lastErr = err
	}
	return
}

// RemoveIndexedLogfile removes both an IndexLogfile and its associated IndexFile
func RemoveIndexedLogfile(path string) (lastErr error) {
	if err := os.Remove(path); err != nil {
		lastErr = err
	}
	if err := os.Remove(path); err != nil {
		lastErr = err
	}
	return
}

// ArchiveFilename returns a standardized name to archive and IndexedLogfile
func ArchiveFilename(path string) string {
	now := time.Now()
	ext := filepath.Ext(path)
	rest := strings.TrimRight(path, ext)

	return fmt.Sprintf("%s-%d%s", rest, now.UTC().UnixNano(), ext)
}

// IndexedLogfile structure
type IndexedLogfile struct {
	sync.Mutex
	path       string
	fd         *os.File
	writer     *gzip.Writer
	indexEntry IndexEntry
}

// OpenIndexedLogfile opens an IndexedLogfile
func OpenIndexedLogfile(path string) (l *IndexedLogfile, err error) {
	l = &IndexedLogfile{path: path}
	if l.fd, err = os.OpenFile(path, os.O_APPEND|os.O_RDWR|os.O_CREATE, DefaultLogPerm); err != nil {
		return
	}

	if err == nil {
		l.writer = gzip.NewWriter(l.fd)
	}

	err = l.resetIndexEntry()
	return
}

// IndexFileFromPath returns a standardized IndexFile name from a path
func IndexFileFromPath(path string) string {
	return fmt.Sprintf("%s%s", path, IndexExt)
}

func (f *IndexedLogfile) resetIndexEntry() (err error) {
	f.indexEntry = IndexEntry{}
	if f.indexEntry.Offset, err = f.size(); err != nil {
		return fmt.Errorf("failed to reset index entry: %w", err)
	}
	return
}

// IndexFile returns the path of the IndexFile associated to the IndexedLogfile
func (f *IndexedLogfile) IndexFile() string {
	return fmt.Sprintf("%s%s", f.path, IndexExt)
}

func (f *IndexedLogfile) size() (size int64, err error) {
	var saved int64

	// we save current offset
	if saved, err = f.fd.Seek(0, io.SeekCurrent); err != nil {
		return
	}

	// we get the file size
	if size, err = f.fd.Seek(0, io.SeekEnd); err != nil {
		return
	}

	// we restore the offset
	if _, err = f.fd.Seek(saved, io.SeekStart); err != nil {
		return
	}

	return
}

// Size returns the size of the IndexedLogfile
func (f *IndexedLogfile) Size() (size int64, err error) {
	f.Lock()
	defer f.Unlock()
	return f.size()

}

// ReadRawEvents reads n RawEvents located at offset in IndexedLogfile
func (f *IndexedLogfile) ReadRawEvents(offset int64, n int64) (events []*RawEvent, err error) {
	f.Lock()
	defer f.Unlock()
	var r *gzip.Reader
	var saved int64
	var s *bufio.Scanner

	events = make([]*RawEvent, 0, n)

	// we save current offset
	if saved, err = f.fd.Seek(0, io.SeekCurrent); err != nil {
		return
	}

	// we go at wanted offset
	if _, err = f.fd.Seek(offset, io.SeekStart); err != nil {
		return
	}

	if r, err = gzip.NewReader(f.fd); err != nil {
		goto Cleanup
	}
	defer r.Close()

	s = bufio.NewScanner(r)
	for s.Scan() && int64(len(events)) < n {
		var raw *RawEvent
		if raw, err = DecodeRawEvent(s.Bytes()); err != nil {
			return
		}
		events = append(events, raw)
	}

Cleanup:
	// we restore the offset
	if _, e := f.fd.Seek(saved, io.SeekStart); e != nil {
		err = e
		return
	}

	return
}

// WriteRawEventWithTimestamp writes a RawEvent with an associated event timestamp in the IndexLogfile
func (f *IndexedLogfile) WriteRawEventWithTimestamp(e *RawEvent, timestamp time.Time) (n int, err error) {
	f.Lock()
	defer f.Unlock()

	var b []byte

	timestamp = stdTime(timestamp)

	// we go at the end of file
	if _, err = f.fd.Seek(0, io.SeekEnd); err != nil {
		return
	}

	// we update timestamps only if write succeded
	b = append(e.Encode(), '\n')
	if n, err = f.writer.Write(b); err == nil {
		f.indexEntry.UpdateTime(timestamp)

		// we increment the event counter
		f.indexEntry.EventCount += 1
	}

	return
}

// WriteRawEvent writes a RawEvent in IndexLogfile taking the event timestamp as reference time
func (f *IndexedLogfile) WriteRawEvent(e *RawEvent) (n int, err error) {
	return f.WriteRawEventWithTimestamp(e, e.Timestamp)
}

func (f *IndexedLogfile) flush() (err error) {
	var indexFd *os.File

	// we commit to index file only if we wrote at least one event
	if f.indexEntry.EventCount > 0 {
		header := !fsutil.Exists(f.IndexFile())
		if indexFd, err = os.OpenFile(f.IndexFile(), os.O_APPEND|os.O_RDWR|os.O_CREATE, utils.DefaultPerms); err != nil {
			return
		}
		defer indexFd.Close()

		if header {
			if _, err = indexFd.WriteString(IndexHeader + "\n"); err != nil {
				return fmt.Errorf("failed to write index file: %w", err)
			}
		}

		if _, err = indexFd.WriteString(f.indexEntry.ToCSV() + "\n"); err != nil {
			return fmt.Errorf("failed to write index file: %w", err)
		}

		if err = f.writer.Flush(); err != nil {
			return fmt.Errorf("failed at flushing gzip writer: %w", err)
		}
		return f.resetIndexEntry()
	}
	return
}

// Flush flushes the IndexedLogfile to disk
func (f *IndexedLogfile) Flush() (err error) {
	f.Lock()
	defer f.Unlock()

	return f.flush()
}

// Close flushes and closes an IndexedLogfile
func (f *IndexedLogfile) Close() (err error) {
	f.Lock()
	defer f.Unlock()

	if err = f.flush(); err != nil {
		return
	}

	// we close gzip writer
	f.writer.Close()
	// close the log file
	if e := f.fd.Close(); e != nil {
		err = e
	}
	return
}
