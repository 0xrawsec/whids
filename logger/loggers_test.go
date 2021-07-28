package logger

import (
	"encoding/json"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/utils"
)

var (
	events = []string{
		// regular log
		`{"Event":{"EventData":{"EventType":"CreateKey","Image":"C:\\Windows\\servicing\\TrustedInstaller.exe","ProcessGuid":"{49F1AF32-38C1-5AC7-0000-00105E5D0B00}","ProcessId":"2544","TargetObject":"HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed","UtcTime":"2018-04-06 20:07:14.423"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA02.caldera.loc","Correlation":{},"EventID":"12","EventRecordID":"886970","Execution":{"ProcessID":"1456","ThreadID":"1712"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"12","TimeCreated":{"SystemTime":"2018-04-06T09:07:14.424360200Z"},"Version":"2"}}}`,
		// alert log
		`{"Event":{"EventData":{"CreationUtcTime":"2018-02-26 16:28:13.169","Image":"C:\\Program Files\\cagent\\cagent.exe","ProcessGuid":"{49F1AF32-11B0-5A90-0000-0010594E0100}","ProcessId":"1216","TargetFilename":"C:\\commander.exe","UtcTime":"2018-02-26 16:28:13.169"},"GeneInfo":{"Criticality":10,"Signature":["ExecutableFileCreated","NewExeCreatedInRoot"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"11","EventRecordID":"1274413","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"11","TimeCreated":{"SystemTime":"2018-02-26T16:28:13.185436300Z"},"Version":"2"}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"powershell\" -command -","Company":"Microsoft Corporation","CurrentDirectory":"C:\\Windows\\system32\\","Description":"Windows PowerShell","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=5330FEDAD485E0E4C23B2ABE1075A1F984FDE9FC,MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","IntegrityLevel":"System","LogonGuid":"{49F1AF32-11AE-5A90-0000-0020E7030000}","LogonId":"0x3e7","ParentCommandLine":"C:\\commander.exe -f","ParentImage":"C:\\commander.exe","ParentProcessGuid":"{49F1AF32-359D-5A94-0000-0010A9530C00}","ParentProcessId":"3068","ProcessGuid":"{49F1AF32-35A0-5A94-0000-0010FE5E0C00}","ProcessId":"1244","Product":"Microsoft® Windows® Operating System","TerminalSessionId":"0","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2018-02-26 16:28:16.514"},"GeneInfo":{"Criticality":10,"Signature":["HeurSpawnShell","PowershellStdin"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"1","EventRecordID":"1274784","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"1","TimeCreated":{"SystemTime":"2018-04-06T16:28:16.530122800Z"},"Version":"5"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"GeneInfo":{"Criticality":10,"Signature":["HeurMaliciousAccess","MaliciousLsassAccess","SuspWriteAccess","SuspiciousLsassAccess"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"2018-02-26T16:43:26.447894800Z"},"Version":"3"}}}`,
	}
)

const (
	day   = time.Hour * 24
	month = day * 30
)

func emitEvents(count int, random bool) (ce chan *evtx.GoEvtxMap) {
	timecreatedPath := evtx.Path("/Event/System/TimeCreated/SystemTime")
	ce = make(chan *evtx.GoEvtxMap)
	go func() {
		defer close(ce)
		for i := 0; i < count; i++ {
			e := new(evtx.GoEvtxMap)
			i := rand.Int() % len(events)
			err := json.Unmarshal([]byte(events[i]), e)
			newTimestamp := time.Now()
			if random {
				delayMin := time.Duration(rand.Int()%120) * time.Minute
				if rand.Int()%2 == 0 {
					newTimestamp = newTimestamp.Add(-delayMin)
				} else {
					newTimestamp = newTimestamp.Add(delayMin)
				}
			}
			e.Set(&timecreatedPath, newTimestamp.Format(time.RFC3339Nano))
			if err != nil {
				log.Errorf("Cannot unmarshall event")
			}
			ce <- e
		}
	}()
	return
}

func timeSearch(t *testing.T, s *EventSearcher, start, stop time.Time, key string, count, skip int) (n int) {
	var prev *RawEvent
	var bytesR int
	timer := time.Now()
	for e := range s.Events(start, stop, key, count, skip) {
		// we control events are comming in good order
		if prev != nil {
			if prev.Timestamp.After(e.Timestamp) {
				t.Errorf("Events are not ordered: %s after %s", prev.Timestamp.UTC(), e.Timestamp.UTC())
			}
		}
		prev = e
		bytesR += len(e.data)
		n++
	}
	delta := time.Since(timer)
	t.Logf("")
	t.Logf("Time to read %d events: %s", count, delta)
	t.Logf("Read throughput: %.1f MB/s", float64(bytesR)/(utils.Mega*delta.Seconds()))
	t.Logf("Total size read: %d MB", bytesR/utils.Mega)
	if s.Err() != nil {
		t.Error(s.Err())
		t.FailNow()
	}
	return
}
func TestEventLogger(t *testing.T) {
	var nExpEvents int

	wg := sync.WaitGroup{}
	root := "data/logs"
	nroutines := 2000
	bytesR, bytesW := 0, 0
	key := "03e31275-2277-d8e0-bb5f-480fac7ee4ef"

	l := NewEventLogger(root, "logs.gz", utils.Mega*1)
	defer l.Close()
	os.RemoveAll("data/logs")
	start := time.Now()
	for i := 0; i < nroutines; i++ {
		wg.Add(1)
		// simulate concurrent writes
		nevents := rand.Int() % 100
		nExpEvents += nevents
		go func() {
			defer wg.Done()
			id := l.InitTransaction()
			for e := range emitEvents(nevents, false) {
				if n, err := l.WriteEvent(id, key, e); err != nil {
					t.Errorf("cannot write event: %s", err)
				} else {
					bytesW += n
				}
			}
			l.CommitTransaction()
			// attempts to write files out of a transaction
			for e := range emitEvents(10, false) {
				if _, err := l.WriteEvent(id, key, e); err == nil {
					t.Errorf("writing out of a transaction is not allowed")
				}
			}
		}()
	}
	wg.Wait()
	delta := time.Since(start)
	t.Logf("Time to write files: %s", delta)
	t.Logf("Total size written (uncompressed): %.1fMB", float64(bytesW)/utils.Mega)
	t.Logf("Write throughput: %.1fMB/s", float64(bytesW)/(utils.Mega*delta.Seconds()))

	if l.CountFiles() != 0 {
		t.Errorf("All files should be closed, %d files still opened", l.CountFiles())
	}

	now := time.Now()
	skip := rand.Int() % nExpEvents
	s := NewEventSearcher(root)
	defer s.Close()

	var prev *RawEvent
	count := 0
	timer := time.Now()
	for e := range s.Events(now.Add(-1*month), now.Add(1*month), key, nExpEvents, skip) {
		// compute size for throughput
		bytesR += len(e.data)

		if prev != nil {
			// we control events are comming in good order
			if prev.Timestamp.After(e.Timestamp) {
				t.Errorf("Events are not ordered: %s after %s", prev.Timestamp.UTC(), e.Timestamp.UTC())
			}
		}
		prev = e
		count++
	}

	delta = time.Since(timer)
	t.Logf("Time to read events: %s", time.Since(timer))
	t.Logf("Read throughput: %.1f MB/s", float64(bytesR)/(utils.Mega*delta.Seconds()))
	t.Logf("Total size read: %d MB", bytesR/utils.Mega)

	if s.Err() != nil {
		t.Error(s.Err())
		t.FailNow()
	}

	if count != nExpEvents-skip {
		t.Errorf("(written) %d != %d (read)", nExpEvents, count)
	}

	t.Logf("Events read: %d", count)

	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 100000, 1000)
	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 50000, 1000)
	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 10000, 10000)
	timeSearch(t, s, now.Add(-1*month), now.Add(1*month), key, 1000, 1000)
}
