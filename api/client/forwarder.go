package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/fileutils"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/fsutil/logfile"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/api/client/config"
	"github.com/0xrawsec/whids/utils"
)

const (
	// DefaultLogfileSize default forwarder logfile size
	DefaultLogfileSize = logfile.MB * 5
	// DiskSpaceThreshold allow 1GB of queued events
	DiskSpaceThreshold = logfile.GB
	// MinRotationInterval is the minimum rotation interval allowed
	MinRotationInterval = time.Minute
)

// Forwarder structure definition
type Forwarder struct {
	sync.Mutex
	sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	fwdConfig *config.Forwarder
	logfile   logfile.LogFile

	Client      *ManagerClient
	TimeTresh   time.Duration
	Sleep       time.Duration
	EventTresh  uint64
	Pipe        *bytes.Buffer
	EventsPiped uint64
	Local       bool
}

// NewForwarder creates a new Forwarder structure
// Todo: needs update with client
func NewForwarder(ctx context.Context, c *config.Forwarder) (*Forwarder, error) {
	var err error

	cctx, cancel := context.WithCancel(ctx)

	// Initialize the Forwarder
	// TODO: better organize forwarder configuration
	co := Forwarder{
		ctx:       cctx,
		cancel:    cancel,
		fwdConfig: c,
		TimeTresh: time.Second * 10,
		Sleep:     time.Second,
		// Writing events too quickly has a perf impact
		EventTresh: 500,
		Pipe:       new(bytes.Buffer),
		Local:      c.Local,
	}

	if !co.Local {
		if co.Client, err = NewManagerClient(&c.Client); err != nil {
			return nil, fmt.Errorf("field to initialize manager client: %s", err)
		}
	}

	// queue directory
	if c.Logging.Dir == "" {
		return nil, fmt.Errorf("field \"logs-dir\" is missing from configuration")
	}

	// creating the queue directory
	if !fsutil.Exists(c.Logging.Dir) && !fsutil.IsDir(c.Logging.Dir) {
		// TOCTU may happen here so we double check error code
		if err = os.Mkdir(c.Logging.Dir, utils.DefaultPerms); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("cannot create queue directory : %s", err)
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

// ArchiveLogs archives the old log files not compressed into compressed
func (f *Forwarder) ArchiveLogs() {
	for wi := range fswalker.Walk(f.fwdConfig.Logging.Dir) {
		for _, fi := range wi.Files {
			// fullpath
			fp := filepath.Join(f.fwdConfig.Logging.Dir, fi.Name())
			log.Infof("Archiving old log: %s", fp)

			if !strings.HasSuffix(fp, ".gz") {
				if err := fileutils.GzipFile(fp); err != nil {
					log.Errorf("Failed to archive log: %s", err)
				}
			}
		}
	}
}

// PipeEvent pipes an event to be sent through the forwarder
func (f *Forwarder) PipeEvent(event interface{}) {
	f.Lock()
	defer f.Unlock()
	f.Pipe.Write(utils.Json(event))
	f.Pipe.WriteByte('\n')
	f.EventsPiped++
}

// Save save the piped events to the disks
func (f *Forwarder) Save() (err error) {
	log.Debugf("Collector saved logs to be sent later on")

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
		//lf := filepath.Join(f.fwdConfig.LogConf.Dir, "alerts.gz")
		lf := filepath.Join(f.fwdConfig.Logging.Dir, "alerts.log")
		ri := f.fwdConfig.Logging.RotationInterval
		log.Infof("Rotating logfile every %s", ri)
		if f.logfile, err = logfile.OpenTimeRotateLogFile(lf, utils.DefaultPerms, ri); err != nil {
			return
		}
	}
	_, err = f.logfile.Write(f.Pipe.Bytes())
	return
}

// HasQueuedEvents checks whether some events are waiting to be sent
func (f *Forwarder) HasQueuedEvents() bool {
	for wi := range fswalker.Walk(f.fwdConfig.Logging.Dir) {
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
	for wi := range fswalker.Walk(f.fwdConfig.Logging.Dir) {
		for _, fi := range wi.Files {
			// initialization
			if olderTime == empty {
				olderTime = fi.ModTime()
				older = filepath.Join(f.fwdConfig.Logging.Dir, fi.Name())
				continue
			}
			// check if we have an older file
			if fi.ModTime().Before(olderTime) {
				olderTime = fi.ModTime()
				older = filepath.Join(f.fwdConfig.Logging.Dir, fi.Name())
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
	for wi := range fswalker.Walk(f.fwdConfig.Logging.Dir) {
		for _, fi := range wi.Files {
			dp += fi.Size()
		}
	}
	return dp
}

// Here we rely on the fact that the layout of the directory is known
// and should be alert.log, alert.log.1, alert.log.2.gz, alert.log.3.gz ...
// if we append in reverse order, older files appears first in the list
func (f *Forwarder) listLogfiles() (files []string) {
	files = make([]string, 0)
	for wi := range fswalker.Walk(f.fwdConfig.Logging.Dir) {
		for _, fi := range wi.Files {
			fp := filepath.Join(f.fwdConfig.Logging.Dir, fi.Name())
			files = append([]string{fp}, files...)
		}
	}
	return
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

	// returns if Manager is not up, this prevents closing logfile
	// for nothing
	if !f.Client.IsServerUp() {
		return
	}

	log.Info("Processing queued files")

	if f.logfile != nil {
		f.logfile.Close()
	}

	// Reset logfile for latter Save function use
	f.logfile = nil
	//for wi := range fswalker.Walk(f.fwdConfig.Logging.Dir) {
	//for _, fi := range wi.Files {
	for _, fp := range f.listLogfiles() {
		// fullpath
		//fp := filepath.Join(f.fwdConfig.Logging.Dir, fi.Name())
		//log.Debug("Processing queued file: %s", fp)
		log.Infof("Processing queued file: %s", fp)
		fd, err := os.Open(fp)
		if err != nil {
			log.Errorf("Failed to open queued file (%s): %s", fp, err)
			continue
		}
		switch {
		case strings.HasSuffix(fp, ".gz"):
			var gzr *gzip.Reader
			// the file is gzip so we have to pass a gzip reader to prepCollectReq
			gzr, err = gzip.NewReader(fd)
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
		case strings.HasSuffix(fp, ".log.1"), strings.HasSuffix(fp, ".log"):
			err = f.Client.PostLogs(fd)
			fd.Close()
		}

		// We do not remove the logs if we failed to send
		if err != nil {
			log.Errorf("%s", err)
			continue
		}

		// everything went fine, then we can delete the queued file
		log.Infof("Deleting queue file : %s", fp)
		if err = os.Remove(fp); err != nil {
			log.Errorf("Failed to delete queued file (%s): %s", fp, err)
		}
	}
}

// Reset resets the forwarder
func (f *Forwarder) Reset() {
	f.Pipe.Reset()
	f.EventsPiped = 0
}

// Collect sends the piped event to the remote server
func (f *Forwarder) Collect() {
	var err error

	// Locking collector for sending data
	f.Lock()
	// Unlocking collector after sending data
	defer f.Unlock()
	// Reset the collector
	defer f.Reset()

	// if not a local forwarder
	if !f.Local {
		if err = f.Client.PostLogs(bytes.NewBuffer(f.Pipe.Bytes())); err == nil {
			// no need to save logs on disk
			return
		}
		log.Errorf("%s", err)
	}

	// Save the events in queue directory
	if err = f.Save(); err != nil {
		log.Errorf("Failed to save events: %s", err)
	}
}

// Run starts the Forwarder worker function
func (f *Forwarder) Run() {
	f.Add(1)
	// Process Piped Events
	go func() {
		defer f.Done()

		timer := time.Now()
		for f.ctx.Err() == nil {
			// We have queued events so we try to send them before sending pending events
			// We check if server is up not to close the current logfile if not needed
			if f.HasQueuedEvents() {
				f.ProcessQueue()
			}

			// Sending piped events
			if f.EventsPiped >= f.EventTresh || time.Now().After(timer.Add(f.TimeTresh)) || f.Local {
				// Send out events if there are pending events
				if f.EventsPiped > 0 {
					f.Collect()
				}
				// reset timer
				timer = time.Now()
			}

			time.Sleep(f.Sleep)
		}
	}()
}

// Close closes the forwarder properly
func (f *Forwarder) Close() {

	// forwarder is already closed -> nothing to do
	if f.ctx.Err() != nil {
		return
	}

	// we cancel forwarder's context
	f.cancel()
	// we wait for forwarding routine to terminate
	f.Wait()

	// we collect last events if needed
	if f.EventsPiped > 0 {
		f.Collect()
	}

	// we close logfile
	if f.logfile != nil {
		f.logfile.Close()
	}

	// Close idle connections if not local
	if !f.Local {
		defer f.Client.Close()
	}
}
