package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/scanner"
	"github.com/0xrawsec/golang-utils/sync/semaphore"
)

var (
	fconf = ForwarderConfig{
		Client: cconf,
		Logging: LoggingConfig{
			Dir:              "./data/Queued",
			RotationInterval: "2s",
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
			EnEnptLogs:  true,
		},
		RulesDir:      "./data",
		DumpDir:       "./data/uploads/",
		ContainersDir: "./data/containers",
		TLS: TLSConfig{
			Cert: "./data/cert.pem",
			Key:  "./data/key.pem",
		},
	}

	events = []string{
		// regular log
		`{"Event":{"EventData":{"EventType":"CreateKey","Image":"C:\\Windows\\servicing\\TrustedInstaller.exe","ProcessGuid":"{49F1AF32-38C1-5AC7-0000-00105E5D0B00}","ProcessId":"2544","TargetObject":"HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed","UtcTime":"2018-04-06 20:07:14.423"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA02.caldera.loc","Correlation":{},"EventID":"12","EventRecordID":"886970","Execution":{"ProcessID":"1456","ThreadID":"1712"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"12","TimeCreated":{"SystemTime":"2018-04-06T09:07:14.424360200Z"},"Version":"2"}}}`,
		// alert log
		`{"Event":{"EventData":{"CreationUtcTime":"2018-02-26 16:28:13.169","Image":"C:\\Program Files\\cagent\\cagent.exe","ProcessGuid":"{49F1AF32-11B0-5A90-0000-0010594E0100}","ProcessId":"1216","TargetFilename":"C:\\commander.exe","UtcTime":"2018-02-26 16:28:13.169"},"GeneInfo":{"Criticality":10,"Signature":["ExecutableFileCreated","NewExeCreatedInRoot"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"11","EventRecordID":"1274413","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"11","TimeCreated":{"SystemTime":"2018-02-26T16:28:13.185436300Z"},"Version":"2"}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"powershell\" -command -","Company":"Microsoft Corporation","CurrentDirectory":"C:\\Windows\\system32\\","Description":"Windows PowerShell","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=5330FEDAD485E0E4C23B2ABE1075A1F984FDE9FC,MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","IntegrityLevel":"System","LogonGuid":"{49F1AF32-11AE-5A90-0000-0020E7030000}","LogonId":"0x3e7","ParentCommandLine":"C:\\commander.exe -f","ParentImage":"C:\\commander.exe","ParentProcessGuid":"{49F1AF32-359D-5A94-0000-0010A9530C00}","ParentProcessId":"3068","ProcessGuid":"{49F1AF32-35A0-5A94-0000-0010FE5E0C00}","ProcessId":"1244","Product":"Microsoft® Windows® Operating System","TerminalSessionId":"0","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2018-02-26 16:28:16.514"},"GeneInfo":{"Criticality":10,"Signature":["HeurSpawnShell","PowershellStdin"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"1","EventRecordID":"1274784","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"1","TimeCreated":{"SystemTime":"2018-04-06T16:28:16.530122800Z"},"Version":"5"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"GeneInfo":{"Criticality":10,"Signature":["HeurMaliciousAccess","MaliciousLsassAccess","SuspWriteAccess","SuspiciousLsassAccess"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"2018-02-26T16:43:26.447894800Z"},"Version":"3"}}}`,
	}
)

func dummyEvents(count int) (ce chan *evtx.GoEvtxMap) {
	timecreatedPath := evtx.Path("/Event/System/TimeCreated/SystemTime")
	ce = make(chan *evtx.GoEvtxMap)
	go func() {
		defer close(ce)
		for i := 0; i < count; i++ {
			e := new(evtx.GoEvtxMap)
			i := rand.Int() % len(events)
			err := json.Unmarshal([]byte(events[i]), e)
			e.Set(&timecreatedPath, time.Now().Format(time.RFC3339Nano))
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
	for e := range dummyEvents(nevents) {
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
	for e := range dummyEvents(nevents) {
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
	for e := range dummyEvents(nevents) {
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
	fconf.Logging.RotationInterval = "1h"
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
