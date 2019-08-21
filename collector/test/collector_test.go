package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/scanner"
	"github.com/0xrawsec/golang-utils/sync/semaphore"
	"github.com/0xrawsec/whids/collector"
)

var (
	fconf = collector.ForwarderConfig{
		Client: cconf,
		Logging: collector.LoggingConfig{
			Dir:              "Queued",
			RotationInterval: "2s",
		},
	}

	mconf = collector.ManagerConfig{
		Host:          "",
		Port:          8000,
		Logfile:       "alerts",
		RulesDir:      "./",
		DumpDir:       "./uploads/",
		ContainersDir: "./containers",
	}

	event = `
	{
		"Event": {
		  "EventData": {
			"EventType": "CreateKey",
			"Image": "C:\\Windows\\servicing\\TrustedInstaller.exe",
			"ProcessGuid": "{49F1AF32-38C1-5AC7-0000-00105E5D0B00}",
			"ProcessId": "2544",
			"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed",
			"UtcTime": "2018-04-06 20:07:14.423"
		  },
		  "System": {
			"Channel": "Microsoft-Windows-Sysmon/Operational",
			"Computer": "CALDERA02.caldera.loc",
			"Correlation": {},
			"EventID": "12",
			"EventRecordID": "886970",
			"Execution": {
			  "ProcessID": "1456",
			  "ThreadID": "1712"
			},
			"Keywords": "0x8000000000000000",
			"Level": "4",
			"Opcode": "0",
			"Provider": {
			  "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
			  "Name": "Microsoft-Windows-Sysmon"
			},
			"Security": {
			  "UserID": "S-1-5-18"
			},
			"Task": "12",
			"TimeCreated": {
			  "SystemTime": "2018-04-06T09:07:14.424360200Z"
			},
			"Version": "2"
		  }
		}
	  }	  
	`
)

func dummyEvents(count int) (ce chan *evtx.GoEvtxMap) {
	ce = make(chan *evtx.GoEvtxMap)
	go func() {
		defer close(ce)
		for i := 0; i < count; i++ {
			e := new(evtx.GoEvtxMap)
			err := json.Unmarshal([]byte(event), e)
			if err != nil {
				log.Errorf("Cannot unmarshall event")
			}
			ce <- e
		}
	}()
	return
}

func rm(filename string) {
	os.Remove(filename)
}

func countLinesInGzFile(filepath string) int {
	var line int
	fd, err := os.Open(filepath)
	if err != nil {
		return 0
		log.Errorf("Error counting lines, cannot open file: %s", err)
	}
	defer fd.Close()

	/*r, err := gzip.NewReader(fd)
	if err != nil {
		log.Errorf("Error counting lines, cannot create gzip reader: %s", err)
		return 0
	}
	defer r.Close()*/

	//s := scanner.New(r)
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

func clean(mc *collector.ManagerConfig, fc *collector.ForwarderConfig) {
	rm(mc.Logfile)
	os.RemoveAll(fc.Logging.Dir)
}

func TestForwarderBasic(t *testing.T) {
	nevents := 1000
	testfile := "TestCollector.log.gz"
	key := collector.KeyGen(collector.DefaultKeySize)
	mconf.Logfile = testfile

	clean(&mconf, &fconf)

	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()

	fconf.Client.Key = key
	f, err := collector.NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	f.Run()

	cnt := 0
	for e := range dummyEvents(nevents) {
		if cnt == 500 {
			time.Sleep(2 * time.Second)
		}
		f.PipeEvent(e)
	}
	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(testfile); n != nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nevents)
	}
	log.Infof("Shutting down")

	clean(&mconf, &fconf)
}
func TestCollectorAuthFailure(t *testing.T) {
	nevents := 1000
	testfile := "TestServerAuthFailure.log.gz"
	key := collector.KeyGen(collector.DefaultKeySize)
	serverKey := "rogueserver"
	mconf.Logfile = testfile

	clean(&mconf, &fconf)

	mconf.Key = serverKey
	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()
	defer r.Shutdown()

	fconf.Client.Key = key
	fconf.Client.ServerKey = collector.KeyGen(collector.DefaultKeySize)
	f, err := collector.NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	f.Run()

	cnt := 0
	for e := range dummyEvents(nevents) {
		if cnt == 500 {
			time.Sleep(2 * time.Second)
		}
		f.PipeEvent(e)
	}
	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(testfile); n != 0 {
		t.Errorf("Some events were logged while it should not")
	}

	clean(&mconf, &fconf)
}

func TestCollectorAuthSuccess(t *testing.T) {
	nevents := 1000
	testfile := "TestServerAuthSuccess.log.gz"
	key := collector.KeyGen(collector.DefaultKeySize)
	serverKey := collector.KeyGen(collector.DefaultKeySize)
	mconf.Logfile = testfile

	clean(&mconf, &fconf)

	mconf.Key = serverKey
	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()
	defer r.Shutdown()

	fconf.Client.Key = key
	fconf.Client.ServerKey = serverKey
	f, err := collector.NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	f.Run()

	cnt := 0
	for e := range dummyEvents(nevents) {
		if cnt == 500 {
			time.Sleep(2 * time.Second)
		}
		f.PipeEvent(e)
	}
	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(testfile); n != nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nevents)
	}

	clean(&mconf, &fconf)
}

func TestForwarderParallel(t *testing.T) {
	jobs := semaphore.New(100)
	nclients, nevents := 1000, 1000
	wg := sync.WaitGroup{}
	testfile := "TestCollectorParallel.log.gz"
	rm(testfile)
	key := collector.KeyGen(collector.DefaultKeySize)
	mconf.Logfile = testfile
	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()
	defer r.Shutdown()

	for i := 0; i < nclients; i++ {
		wg.Add(1)
		jobs.Acquire()
		go func() {
			defer jobs.Release()
			defer wg.Done()
			fconf.Client.Key = key
			c, err := collector.NewForwarder(&fconf)
			if err != nil {
				t.Errorf("Failed to create collector: %s", err)
				t.FailNow()
			}
			c.Run()
			for e := range dummyEvents(nevents) {
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
	if n := countLinesInGzFile(testfile); n != nclients*nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nclients*nevents)
	}
	rm(testfile)
}

func TestForwarderQueueBasic(t *testing.T) {
	// cleanup
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	nevents := 1000
	testfile := "TestCollectorQueue.log.gz"
	rm(testfile)
	// Initialize the receiver
	key := collector.KeyGen(collector.DefaultKeySize)
	mconf.Logfile = testfile
	clean(&mconf, &fconf)

	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)

	// Inititialize the forwarder
	fconf.Client.Key = key
	f, err := collector.NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	// Running the forwarder
	f.Run()
	defer f.Close()

	// Sending events
	for e := range dummyEvents(nevents / 2) {
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
	for e := range dummyEvents(nevents / 2) {
		f.PipeEvent(e)
	}

	// reinitialize a Receiver
	r, err = collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()

	time.Sleep(5 * time.Second)

	// shuts down the receiver before counting lines
	r.Shutdown()
	if n := countLinesInGzFile(testfile); n != nevents {
		t.Errorf("Some events were lost on the way: %d logged by server instead of %d sent", n, nevents)
	}
}

func TestForwarderCleanup(t *testing.T) {
	// cleanup
	clean(&mconf, &fconf)
	defer clean(&mconf, &fconf)

	// Change rotation interval not to create unexpected number of files
	fconf.Logging.RotationInterval = "1h"
	// Inititialize the forwarder
	f, err := collector.NewForwarder(&fconf)
	if err != nil {
		t.Errorf("Failed to create collector: %s", err)
		t.FailNow()
	}
	// Running the forwarder
	f.Run()

	// create bogus files inside queue directory
	numberOfFiles := collector.DiskSpaceThreshold / collector.DefaultLogfileSize
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
		for written := 0; written < collector.DefaultLogfileSize; {
			n, _ := fd.Write(buf)
			written += n
		}
		fd.Close()
	}

	// send enough events to trigger cleanup
	for i := 0; i < additionalFiles+3; i++ {
		for e := range dummyEvents(int(f.EventTresh)) {
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
