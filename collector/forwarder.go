package collector

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/fsutil/fswalker"

	"github.com/0xrawsec/golang-utils/fsutil/logfile"

	"github.com/0xrawsec/golang-utils/fsutil"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	CollectURL     = "/collect"
	ServerKeyURL   = "/key"
	UserAgent      = "Whids-Event-Collector/1.0"
	DefaultDirPerm = 0700

	DefaultLogfileSize = logfile.MB * 5
	// DiskSpaceThreshold allow 100MB of queued events
	DiskSpaceThreshold = DefaultLogfileSize * 20
)

var (
	NoProxyTransport http.RoundTripper = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	NoProxyUnsafeTransport http.RoundTripper = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
)

func buildURI(proto, host, port, url string) string {
	url = strings.Trim(url, "/")
	return fmt.Sprintf("%s://%s:%s/%s", proto, host, port, url)

}

// ForwarderConfig structure definition
type ForwarderConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port`
	Proto     string `json:"proto"`
	Key       string `json:"key"`
	ServerKey string `json:"server-key"`
	QueueDir  string `json:"queue-dir"`
	Unsafe    bool   `json:"unsafe"`
}

// Forwarder structure definition
type Forwarder struct {
	sync.Mutex
	httpClient http.Client
	proto      string
	host       string
	port       string
	key        string
	serverKey  string
	queueDir   string
	stop       chan bool
	done       chan bool
	logfile    *logfile.LogFile

	TimeTresh   time.Duration
	EventTresh  uint64
	Pipe        *bytes.Buffer
	EventsPiped uint64
}

// NewForwarder creates a new Forwarder structure
func NewForwarder(c *ForwarderConfig) (*Forwarder, error) {
	var err error

	// Type of HTTP transport to use
	tpt := NoProxyTransport
	if c.Unsafe {
		tpt = NoProxyUnsafeTransport
	}

	// Initialize the Forwarder
	co := Forwarder{
		httpClient: http.Client{Transport: tpt},
		TimeTresh:  time.Second * 10,
		EventTresh: 50,
		Pipe:       new(bytes.Buffer),
		stop:       make(chan bool),
		done:       make(chan bool),
	}
	// host
	co.host = c.Host
	if c.Host == "" {
		return nil, fmt.Errorf("Field \"host\" is missing from configuration")
	}
	// protocol
	co.proto = c.Proto
	if c.Proto == "" {
		co.proto = "https"
	}
	switch co.proto {
	case "http", "https":
	default:
		return nil, fmt.Errorf("Protocol not supported (only http(s))")
	}

	// port
	co.port = fmt.Sprintf("%d", c.Port)
	if c.Port == 0 {
		co.port = DefaultPort
	}

	// key
	co.key = c.Key
	if c.Key == "" {
		return nil, fmt.Errorf("Field \"key\" is missing from configuration")
	}

	// server-key
	co.serverKey = c.ServerKey

	// queue directory
	co.queueDir = c.QueueDir
	if c.QueueDir == "" {
		return nil, fmt.Errorf("Field \"queue-dir\" is missing from configuration")
	}

	// creating the queue directory
	if !fsutil.Exists(co.queueDir) && !fsutil.IsDir(co.queueDir) {
		// TOCTU may happen here so we double check error code
		if err = os.Mkdir(co.queueDir, DefaultDirPerm); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("Cannot create queue directory : %s", err)
		}
	}

	return &co, nil
}

func (f *Forwarder) setHeaders(r *http.Request) {
	r.Header.Add("User-Agent", UserAgent)
	r.Header.Add("Api-Key", f.key)
}

func (f *Forwarder) prepCollectReq(r io.Reader) (*http.Request, error) {
	body := new(bytes.Buffer)
	w := gzip.NewWriter(body)
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	w.Write(b)
	w.Close()
	req, err := http.NewRequest("POST", buildURI(f.proto, f.host, f.port, CollectURL), bytes.NewBuffer(body.Bytes()))
	if err != nil {
		return nil, err
	}
	f.setHeaders(req)
	req.Header.Add("Accept-Encoding", "gzip")
	return req, nil
}

// LogfilePath returns the path of the logfile if it exists else returns empty string
func (f *Forwarder) LogfilePath() string {
	if f.logfile != nil {
		return f.logfile.Path()
	}
	return ""
}

// IsServerAuthEnforced returns true if server authentication is requested by the client
func (f *Forwarder) IsServerAuthEnforced() bool {
	return f.serverKey != ""
}

// IsSafeToSend checks whether the receiver is ready to receive logs
func (f *Forwarder) IsSafeToSend() bool {
	get, err := http.NewRequest("GET", buildURI(f.proto, f.host, f.port, ServerKeyURL), nil)
	if err != nil {
		log.Errorf("Cannot create server key request: %s", err)
		return false
	}
	f.setHeaders(get)
	resp, err := f.httpClient.Do(get)
	if err != nil {
		log.Errorf("Cannot issue server key request: %s", err)
		return false
	}
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			key, _ := ioutil.ReadAll(resp.Body)
			if f.IsServerAuthEnforced() {
				if f.serverKey == string(key) {
					// if the server can be authenticated
					return true
				}
				log.Warn("Failed to authenticate remote server")
				// if the server is not authenticated
				return false
			}
			return true
		}
	}
	return false
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
		// This will reopen the first available queue.gz.X file if several
		lf := filepath.Join(f.queueDir, "queue.gz")
		if f.logfile, err = logfile.OpenFile(lf, DefaultLogPerm, DefaultLogfileSize); err != nil {
			return err
		}
	}
	f.logfile.Write(f.Pipe.Bytes())
	return nil
}

// HasQueuedEvents checks whether some events are waiting to be sent
func (f *Forwarder) HasQueuedEvents() bool {
	for wi := range fswalker.Walk(f.queueDir) {
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
	for wi := range fswalker.Walk(f.queueDir) {
		for _, fi := range wi.Files {
			// initialization
			if olderTime == empty {
				olderTime = fi.ModTime()
				older = filepath.Join(f.queueDir, fi.Name())
				continue
			}
			// check if we have an older file
			if fi.ModTime().Before(olderTime) {
				olderTime = fi.ModTime()
				older = filepath.Join(f.queueDir, fi.Name())
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
	for wi := range fswalker.Walk(f.queueDir) {
		for _, fi := range wi.Files {
			dp += fi.Size()
		}
	}
	return dp
}

// ProcessQueue processes the events queued
func (f *Forwarder) ProcessQueue() {
	f.Lock()
	defer f.Unlock()
	log.Info("Processing queued files")

	// Verify it is safe to send the logs to the manager, if not abort
	if !f.IsSafeToSend() {
		log.Error("Do not process queue, receiver down or authentication issue (client or server)")
		return
	}

	if f.logfile != nil {
		f.logfile.Close()
	}
	// Reset logfile for latter Save function use
	f.logfile = nil
	for wi := range fswalker.Walk(f.queueDir) {
		for _, fi := range wi.Files {
			// fullpath
			fp := filepath.Join(f.queueDir, fi.Name())
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

			// preparing the request
			post, err := f.prepCollectReq(gzr)
			if err != nil {
				log.Errorf("Failed to prepare collect request for queued file (%s): %s", fp, err)
				// close readers
				gzr.Close()
				fd.Close()
				continue
			}
			// we can close the reader since we don't need those anymore
			gzr.Close()
			fd.Close()

			// issuing the request to the server
			resp, err := f.httpClient.Do(post)
			if err != nil {
				log.Errorf("Failed to send queued file (%s): %s", fp, err)
				continue
			}

			// we continue if response is nil
			if resp == nil {
				continue
			}

			// we continue if we receive bad HTTP status
			if resp.StatusCode != 200 {
				log.Errorf("Received wrong HTTP status while sending queued file: %s", resp.Status)
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

// Send sends the piped event to the remote server
func (f *Forwarder) Send() {
	// Locking collector for sending data
	f.Lock()
	// Unlocking collector after sending data
	defer f.Unlock()
	// Reset the collector
	defer f.Reset()

	// Check first if the receiver is up before attempting upload
	if !f.IsSafeToSend() {
		log.Error("Do not process queue, receiver down or authentication issue (client or server)")
		f.Save()
		return
	}

	req, err := f.prepCollectReq(bytes.NewBuffer(f.Pipe.Bytes()))

	if err != nil {
		log.Errorf("Collector failed to prepare request: %s", err)
		// Save the events in queue directory
		if err := f.Save(); err != nil {
			log.Errorf("Failed to save events: %s", err)
		}
		return
	}

	resp, err := f.httpClient.Do(req)
	log.Debugf("Sending %d events to server", f.EventsPiped)
	if err != nil {
		log.Errorf("Collector failed to send events: %s", err)
		// Save the events in queue directory
		if err := f.Save(); err != nil {
			log.Errorf("Failed to save events: %s", err)
		}
		return
	}

	if resp == nil {
		log.Errorf("HTTP response is nil")
		// Save the events in queue directory
		if err := f.Save(); err != nil {
			log.Errorf("Failed to save events: %s", err)
		}
		return
	}

	// Now we are sure resp is not nil
	// Close TCP connection when we are done
	defer resp.Body.Close()
	// HTTP error
	if resp.StatusCode != 200 {
		log.Errorf("Collector received a wrong HTTP status: %s", resp.Status)
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
					f.Send()
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
	f.stop <- true
	// Waiting forwarder stopped routine is done
	<-f.done
	if f.EventsPiped > 0 {
		f.Send()
	}
	if f.logfile != nil {
		f.logfile.Close()
	}
}
