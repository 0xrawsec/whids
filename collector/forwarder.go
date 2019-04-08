package collector

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/fsutil/logfile"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	// DefaultDirPerm default log directory permissions for forwarder
	DefaultDirPerm = 0700
	// DefaultLogfileSize default forwarder logfile size
	DefaultLogfileSize = logfile.MB * 5
	// DiskSpaceThreshold allow 100MB of queued events
	DiskSpaceThreshold = DefaultLogfileSize * 20
)

var ()

func buildURI(proto, host, port, url string) string {
	url = strings.Trim(url, "/")
	return fmt.Sprintf("%s://%s:%s/%s", proto, host, port, url)

}

// ForwarderConfig structure definition
type ForwarderConfig struct {
	Client  ClientConfig `json:"manager-client"`
	LogsDir string       `json:"logs-dir"`
	Local   bool         `json:"local"`
}

// Forwarder structure definition
type Forwarder struct {
	sync.Mutex
	logsDir string
	stop    chan bool
	done    chan bool
	logfile *logfile.LogFile

	Client      *ManagerClient
	TimeTresh   time.Duration
	EventTresh  uint64
	Pipe        *bytes.Buffer
	EventsPiped uint64
	Local       bool
}

// NewForwarder creates a new Forwarder structure
// Todo: needs update with client
func NewForwarder(c *ForwarderConfig) (*Forwarder, error) {
	var err error

	// Initialize the Forwarder
	co := Forwarder{
		TimeTresh:  time.Second * 10,
		EventTresh: 50,
		Pipe:       new(bytes.Buffer),
		stop:       make(chan bool),
		done:       make(chan bool),
		Local:      c.Local,
	}

	if !co.Local {
		if co.Client, err = NewManagerClient(&c.Client); err != nil {
			return nil, fmt.Errorf("Field to initialize manager client: %s", err)
		}
	}

	// queue directory
	co.logsDir = c.LogsDir
	if c.LogsDir == "" {
		return nil, fmt.Errorf("Field \"logs-dir\" is missing from configuration")
	}

	// creating the queue directory
	if !fsutil.Exists(co.logsDir) && !fsutil.IsDir(co.logsDir) {
		// TOCTU may happen here so we double check error code
		if err = os.Mkdir(co.logsDir, DefaultDirPerm); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("Cannot create queue directory : %s", err)
		}
	}

	return &co, nil
}

// LogfilePath returns the path of the logfile if it exists else returns empty string
func (f *Forwarder) LogfilePath() string {
	if f.logfile != nil {
		return f.logfile.Path()
	}
	return ""
}

// PipeEvent pipes an event to be sent through the forwarder
func (f *Forwarder) PipeEvent(e *evtx.GoEvtxMap) {
	f.Lock()
	defer f.Unlock()
	f.Pipe.Write(evtx.ToJSON(e))
	f.Pipe.WriteByte('\n')
	f.EventsPiped++
}

// Save save the piped events to the disks
func (f *Forwarder) Save() error {
	var err error
	log.Infof("Collector saved logs to be sent later on")

	// Clean queued files if needed
	if f.DiskSpaceQueue() > DiskSpaceThreshold {
		log.Infof("Disk space taken by queued events reached %dMB threshold, need cleanup",
			DiskSpaceThreshold/logfile.MB)
		if err := f.CleanOlderQueued(); err != nil {
			log.Errorf("Error attempting to remove older queue file: %s", err)
		}
	}

	if f.logfile == nil {
		// This will reopen the first available alerts.gz.X file if several
		lf := filepath.Join(f.logsDir, "alerts.gz")
		if f.logfile, err = logfile.OpenFile(lf, DefaultLogPerm, DefaultLogfileSize); err != nil {
			return err
		}
	}
	f.logfile.Write(f.Pipe.Bytes())
	return nil
}

// HasQueuedEvents checks whether some events are waiting to be sent
func (f *Forwarder) HasQueuedEvents() bool {
	for wi := range fswalker.Walk(f.logsDir) {
		if len(wi.Files) > 0 {
			return true
		}
	}
	return false
}

// CleanOlderQueued cleans up the older queue file
func (f *Forwarder) CleanOlderQueued() error {
	var older string
	var olderTime time.Time
	empty := time.Time{}
	for wi := range fswalker.Walk(f.logsDir) {
		for _, fi := range wi.Files {
			// initialization
			if olderTime == empty {
				olderTime = fi.ModTime()
				older = filepath.Join(f.logsDir, fi.Name())
				continue
			}
			// check if we have an older file
			if fi.ModTime().Before(olderTime) {
				olderTime = fi.ModTime()
				older = filepath.Join(f.logsDir, fi.Name())
			}
		}
	}
	absOlder, _ := filepath.Abs(older)
	absLogfile, _ := filepath.Abs(f.LogfilePath())
	// prevent from deleting the current file we are working on
	if absLogfile != absOlder {
		log.Infof("Attempt to delete older queue file to make more space: %s", absOlder)
		return os.Remove(absOlder)
	}
	return nil
}

// DiskSpaceQueue compute the disk space (in bytes) taken by queued events
func (f *Forwarder) DiskSpaceQueue() int64 {
	var dp int64
	for wi := range fswalker.Walk(f.logsDir) {
		for _, fi := range wi.Files {
			dp += fi.Size()
		}
	}
	return dp
}

// ProcessQueue processes the events queued
// Todo: needs update with client
func (f *Forwarder) ProcessQueue() {
	f.Lock()
	defer f.Unlock()

	// if it is a local collector no need to process
	if f.Local {
		return
	}

	log.Info("Processing queued files")

	if f.logfile != nil {
		f.logfile.Close()
	}

	// Reset logfile for latter Save function use
	f.logfile = nil
	for wi := range fswalker.Walk(f.logsDir) {
		for _, fi := range wi.Files {
			// fullpath
			fp := filepath.Join(f.logsDir, fi.Name())
			log.Debug("Processing queued file: %s", fp)
			fd, err := os.Open(fp)
			if err != nil {
				log.Errorf("Failed to open queued file (%s): %s", fp, err)
				continue
			}

			// the file is gzip so we have to pass a gzip reader to prepCollectReq
			gzr, err := gzip.NewReader(fd)
			if err != nil {
				log.Errorf("Failed to create gzip reader for queued file (%s): %s", fp, err)
				// close file
				fd.Close()
				continue
			}

			err = f.Client.PostLogs(gzr)

			// we can close the reader since we don't need those anymore
			gzr.Close()
			fd.Close()

			// We do not remove the logs if we failed to send
			if err != nil {
				log.Errorf("%s", err)
				continue
			}

			// everything went fine, then we can delete the queued file
			if err = os.Remove(fp); err != nil {
				log.Errorf("Failed to delete queued file (%s): %s", fp, err)
			}
		}
	}
}

// Reset resets the forwarder
func (f *Forwarder) Reset() {
	f.Pipe.Reset()
	f.EventsPiped = 0
}

// Collect sends the piped event to the remote server
// Todo: needs update with client
func (f *Forwarder) Collect() {
	// Locking collector for sending data
	f.Lock()
	// Unlocking collector after sending data
	defer f.Unlock()
	// Reset the collector
	defer f.Reset()

	// if not a local forwarder
	if !f.Local {
		err := f.Client.PostLogs(bytes.NewBuffer(f.Pipe.Bytes()))

		if err != nil {
			log.Errorf("%s", err)
			// Save the events in queue directory
			if err := f.Save(); err != nil {
				log.Errorf("Failed to save events: %s", err)
			}
		}
	} else {
		// Save the events in queue directory
		if err := f.Save(); err != nil {
			log.Errorf("Failed to save events: %s", err)
		}
	}
}

// Run starts the Forwarder worker function
func (f *Forwarder) Run() {
	// Process Piped Events
	go func() {
		// defer signal that we are done
		defer func() { f.done <- true }()
		timer := time.Now()
		for {
			select {
			case <-f.stop:
				return
			default:
			}
			// We have queued events so we try to send them before sending pending events
			if f.HasQueuedEvents() {
				f.ProcessQueue()
			}
			// Sending piped events
			if f.EventsPiped >= f.EventTresh || time.Now().After(timer.Add(f.TimeTresh)) {
				// Send out events if there are pending events
				if f.EventsPiped > 0 {
					f.Collect()
				}
				// reset timer
				timer = time.Now()
			}
			time.Sleep(time.Second)
		}
	}()
}

// Close closes the forwarder properly
func (f *Forwarder) Close() {
	// Close idle connections if not local
	if !f.Local {
		defer f.Client.Close()
	}
	f.stop <- true
	// Waiting forwarder stopped routine is done
	<-f.done
	if f.EventsPiped > 0 {
		f.Collect()
	}
	if f.logfile != nil {
		f.logfile.Close()
	}
}
