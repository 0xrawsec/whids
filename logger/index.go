package logger

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/golang-utils/datastructs"
)

// IndexFile represents an opened index file
type IndexFile struct {
	path string
	fd   *os.File
	s    *bufio.Scanner
	i    int
}

// OpenIndexFile opens an index file from a path
func OpenIndexFile(path string) (inf *IndexFile, err error) {
	inf = &IndexFile{path: path}
	if inf.fd, err = os.Open(path); err != nil {
		return
	}
	inf.s = bufio.NewScanner(inf.fd)
	return
}

// LogfilePaths returns the name of the IndexedLogFile
// associated to the IndexFile
func (inf *IndexFile) LogfilePath() string {
	return strings.TrimSuffix(inf.path, IndexExt)
}

// Next returns the next IndexEntry
// stop condition if ie == nil or err != nil
func (inf *IndexFile) Next() (ie *IndexEntry, err error) {
	// we skip header
	if inf.i == 0 {
		if ok := inf.s.Scan(); !ok {
			err = inf.s.Err()
			return
		}
	}
	// we read one line
	if ok := inf.s.Scan(); !ok {
		err = inf.s.Err()
		return
	}
	ie, err = IndexEntryFromCSV(inf.s.Text())
	ie.indexFile = inf
	inf.i++
	return
}

// Close closes the underlying file descriptor
func (inf *IndexFile) Close() error {
	return inf.fd.Close()
}

// IndexEntry represents encodes information about the
// events written in an IndexedLogfile
type IndexEntry struct {
	indexFile  *IndexFile
	Start      time.Time `json:"start"`
	Stop       time.Time `json:"stop"`
	Offset     int64     `json:"offset"`
	EventCount int64     `json:"count"`
}

// IndexEntryFromCSV returns an IndexEntry from a CSV line
func IndexEntryFromCSV(line string) (ie *IndexEntry, err error) {
	ie = &IndexEntry{}
	fields := strings.Split(strings.Trim(line, "\n"), ",")

	if ie.Start, err = parseTime(fields[0]); err != nil {
		return
	}

	if ie.Stop, err = parseTime(fields[1]); err != nil {
		return
	}

	if ie.Offset, err = strconv.ParseInt(fields[2], 0, 64); err != nil {
		return
	}

	if ie.EventCount, err = strconv.ParseInt(fields[3], 0, 64); err != nil {
		return
	}

	return
}

// UpdateTime must be used to update the Start and Stop timestamps
// of the IndexEntry structure
func (i *IndexEntry) UpdateTime(t time.Time) {
	if i.Start.IsZero() && i.Stop.IsZero() {
		i.Start = t
		i.Stop = t
		return
	}

	if t.Before(i.Start) {
		i.Start = t
	}

	if t.After(i.Stop) {
		i.Stop = t
	}
}

// Implements datastructs.Sortable interface
func (i *IndexEntry) Less(other *datastructs.Sortable) bool {
	return i.Start.Before((*other).(*IndexEntry).Start)
}

// In returns true if entry is fully in time range start < entry < stop
func (i *IndexEntry) In(start time.Time, stop time.Time) bool {
	return i.Start.After(start) && i.Stop.Before(stop)
}

// Overlaps returns true if entry has overlapping time with time range
func (i *IndexEntry) Overlaps(start time.Time, stop time.Time) bool {
	return (i.Start.After(start) && i.Stop.Before(stop)) || i.Contains(start) || i.Contains(stop) || (start.After(i.Start) && stop.Before(i.Stop))
}

// Contains returns true if time is in between entry start and stop
func (i *IndexEntry) Contains(ts time.Time) bool {
	return (ts.After(i.Start) && ts.Before(i.Stop)) || i.Start == ts || i.Stop == ts
}

// Before returns true if index is before another
func (i *IndexEntry) Before(other *IndexEntry) bool {
	return i.Start.Before(other.Start) && i.Stop.Before(other.Stop)
}

// ToCSV marshals an IndexEntry to CSV data
func (i *IndexEntry) ToCSV() string {
	return fmt.Sprintf("%s,%s,%d,%d", fmtTime(i.Start), fmtTime(i.Stop), i.Offset, i.EventCount)
}
