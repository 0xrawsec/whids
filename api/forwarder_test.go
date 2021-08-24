package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/golang-utils/scanner"
	"github.com/0xrawsec/golang-utils/sync/semaphore"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
)

var (
	fconf = ForwarderConfig{
		Client: cconf,
		Logging: LoggingConfig{
			Dir:              "./data/Queued",
			RotationInterval: time.Second * 2,
		},
	}

	mconf = ManagerConfig{
		AdminAPI: AdminAPIConfig{
			Host:  "localhost",
			Port:  8001,
			Users: []AdminUser{{Key: "testing"}},
		},
		EndpointAPI: EndpointAPIConfig{
			Host: "",
			Port: 8000,
		},
		Logging: ManagerLogConfig{
			Root:        "./data/logs",
			LogBasename: "alerts",
			//EnEnptLogs:  true,
		},
		RulesDir:      "./data",
		DumpDir:       "./data/uploads/",
		ContainersDir: "./data/containers",
		TLS: TLSConfig{
			Cert: "./data/cert.pem",
			Key:  "./data/key.pem",
		},
	}

	eventFile = "./data/events.json"
	events    = make([]event.EdrEvent, 0)
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

func emitEvents(count int) (ce chan *event.EdrEvent) {
	ce = make(chan *event.EdrEvent)
	go func() {
		defer close(ce)
		for i := 0; i < count; i++ {
			i := rand.Int() % len(events)
			e := events[i]
			e.Event.System.TimeCreated.SystemTime = time.Now()
			ce <- &e
		}
	}()
	return
}

func readerFromEvents(count int) io.Reader {
	tmp := make([]string, 0, count)
	for event := range emitEvents(count) {
		tmp = append(tmp, string(utils.Json(event)))
	}
	return bytes.NewBufferString(strings.Join(tmp, "\n"))
}

func countLinesInGzFile(filepath string) int {
	var line int
	fd, err := os.Open(filepath)
	log.Infof("Counting in %s", filepath)
	if err != nil {
		panic(fmt.Sprintf("Error counting lines, cannot open file: %s", err))
	}
	defer fd.Close()

	s := scanner.New(fd)
	s.Error = func(err error) {
		log.Errorf("Error in countLinesInGzFile: %s", err)
	}
	s.InitWhitespace("\n")
	for tok := range s.Tokenize() {
		if tok == "\n" {
			line++
		}
	}
	return line
}

func clean(mc *ManagerConfig, fc *ForwarderConfig) {
	os.RemoveAll(mc.Logging.Root)
	os.RemoveAll(fc.Logging.Dir)
}

func logfileFromConfig(c ManagerConfig) string {
	return filepath.Join(c.Logging.Root, c.Logging.LogBasename)
}

func TestForwarderBasic(t *testing.T) {
	clean(&mconf, &fconf)
	//defer clean(&mconf, &fconf)

	nevents := 1000
	testfile := "Testlog.gz"
	key := KeyGen(DefaultKeySize)
	mconf.Logging.LogBasename = testfile

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()

	fconf.Client.Key = key
	f, err := NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	f.Run()

	cnt := 0
	for e := range emitEvents(nevents) {
		if cnt == 500 {
			time.Sleep(2 * time.Second)
		}
		f.PipeEvent(e)
	}
	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(logfileFromConfig(mconf)); n != nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nevents)
	}
	log.Infof("Shutting down")
}

func TestCollectorAuthFailure(t *testing.T) {
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	nevents := 1000
	testfile := "TestServerAuthFailure.log.gz"
	key := KeyGen(DefaultKeySize)
	serverKey := "rogueserver"
	mconf.Logging.LogBasename = testfile

	clean(&mconf, &fconf)

	mconf.EndpointAPI.ServerKey = serverKey
	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	fconf.Client.Key = key
	fconf.Client.ServerKey = KeyGen(DefaultKeySize)
	f, err := NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	f.Run()

	cnt := 0
	for e := range emitEvents(nevents) {
		if cnt == 500 {
			time.Sleep(2 * time.Second)
		}
		f.PipeEvent(e)
	}
	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(logfileFromConfig(mconf)); n != 0 {
		t.Errorf("Some events were logged while it should not")
	}
}

func TestCollectorAuthSuccess(t *testing.T) {
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	nevents := 1000
	testfile := "TestServerAuthSuccess.log.gz"
	key := KeyGen(DefaultKeySize)
	serverKey := KeyGen(DefaultKeySize)
	mconf.Logging.LogBasename = testfile
	mconf.EndpointAPI.ServerKey = serverKey

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	fconf.Client.Key = key
	fconf.Client.ServerKey = serverKey
	f, err := NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	f.Run()

	cnt := 0
	for e := range emitEvents(nevents) {
		if cnt == 500 {
			time.Sleep(2 * time.Second)
		}
		f.PipeEvent(e)
	}
	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(logfileFromConfig(mconf)); n != nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nevents)
	}
}

func TestForwarderParallel(t *testing.T) {
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	jobs := semaphore.New(100)
	nclients, nevents := 1000, 1000
	wg := sync.WaitGroup{}
	testfile := "TestCollectorParallel.log.gz"
	key := KeyGen(DefaultKeySize)
	mconf.Logging.LogBasename = testfile

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	for i := 0; i < nclients; i++ {
		wg.Add(1)
		jobs.Acquire()
		go func() {
			defer jobs.Release()
			defer wg.Done()
			fconf.Client.Key = key
			c, err := NewForwarder(&fconf)
			if err != nil {
				t.Errorf("Failed to create collector: %s", err)
				t.FailNow()
			}
			c.Run()
			for e := range emitEvents(nevents) {
				c.PipeEvent(e)
			}
			time.Sleep(2 * time.Second)
			c.Close()
		}()
	}
	wg.Wait()
	time.Sleep(2 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(logfileFromConfig(mconf)); n != nclients*nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nclients*nevents)
	}
}

func TestForwarderQueueBasic(t *testing.T) {
	// cleanup
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	nevents := 1000
	testfile := "TestCollectorQueue.log"
	outfile := fmt.Sprintf("%s.1", testfile)

	// Initialize the receiver
	key := KeyGen(DefaultKeySize)
	mconf.Logging.LogBasename = testfile
	clean(&mconf, &fconf)

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)

	// Inititialize the forwarder
	fconf.Client.Key = key
	f, err := NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	// Running the forwarder
	f.Run()
	defer f.Close()

	// Sending events
	for e := range emitEvents(nevents / 2) {
		f.PipeEvent(e)
	}

	// Running the receiver after the events have been
	// piped by the forwarder, to queue events
	time.Sleep(5 * time.Second)
	r.Run()

	// Wait the forwarder send the events
	time.Sleep(5 * time.Second)

	// Simulate first shutdown
	r.Shutdown()

	// Sending another wave of events
	for e := range emitEvents(nevents / 2) {
		f.PipeEvent(e)
	}

	// reinitialize a Receiver
	r, err = NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()

	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(filepath.Join(mconf.Logging.Root, outfile)); n != nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nevents)
	}
}

func TestForwarderCleanup(t *testing.T) {
	// cleanup
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	// Change rotation interval not to create unexpected number of files
	fconf.Logging.RotationInterval = time.Hour
	// Inititialize the forwarder
	f, err := NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	// Running the forwarder
	f.Run()

	// create bogus files inside queue directory
	numberOfFiles := DiskSpaceThreshold / DefaultLogfileSize
	additionalFiles := 10
	for i := 0; i < numberOfFiles+additionalFiles; i++ {
		fp := filepath.Join(fconf.Logging.Dir, fmt.Sprintf("queue.bogus.%d", i))
		fd, err := os.Create(fp)
		if err != nil {
			t.Errorf("Failed to create bogus file: %s", err)
			t.FailNow()
		}

		buf := make([]byte, 4096)
		rand.Read(buf)
		for written := 0; written < DefaultLogfileSize; {
			n, _ := fd.Write(buf)
			written += n
		}
		fd.Close()
	}

	// send enough events to trigger cleanup
	for i := 0; i < additionalFiles+3; i++ {
		for e := range emitEvents(int(f.EventTresh)) {
			f.PipeEvent(e)
		}
		time.Sleep(2 * time.Second)
	}

	files, _ := ioutil.ReadDir(fconf.Logging.Dir)
	if len(files) != numberOfFiles {
		t.Errorf("Unexpected number of files remaining in the directory")
		t.FailNow()
	}

	defer f.Close()
}
