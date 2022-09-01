package event

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/toast"
)

var (
	eventFile = "./data/events.json"
	events    = make([]EdrEvent, 0)
	eventData = "/Event/EventData/"
)

const (
	day   = time.Hour * 24
	month = day * 30
)

func init() {
	data, err := os.ReadFile(eventFile)
	if err != nil {
		panic(err)
	}
	for line := range readers.Readlines(bytes.NewBuffer(data)) {
		event := EdrEvent{}
		json.Unmarshal(line, &event)
		events = append(events, event)
	}
}

func emitEvents(count int, random bool) (ce chan *EdrEvent) {
	ce = make(chan *EdrEvent)
	go func() {
		defer close(ce)
		for i := 0; i < count; i++ {
			i := rand.Int() % len(events)
			// we need to use a copy of the event as event
			// contains some pointer making shalow copy
			// copying that pointer too
			e := events[i].Copy()
			newTimestamp := time.Now()
			if random {
				delayMin := time.Duration(rand.Int()%120) * time.Minute
				if rand.Int()%2 == 0 {
					newTimestamp = newTimestamp.Add(-delayMin)
				} else {
					newTimestamp = newTimestamp.Add(delayMin)
				}
			}
			e.Event.System.TimeCreated.SystemTime = newTimestamp
			ce <- e
		}
	}()
	return
}

func TestEventWithAction(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)
	str := `{"Event":{"EventData":{"AccessList":"%%4416\r\n\t\t\t\t","AccessMask":"0x1","CommandLine":"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" ","HandleId":"0x1350","ImageHashes":"SHA1=957004ABEEF46EF5B5365F668F26868434E4D040,MD5=74859601FB4BEEA84B40D874CCB56CAB,SHA256=A35C86CCD3E26316C45A0E63EFA9CDD1E9D3B01B23F7829EAD9106FA5340066D,IMPHASH=891D2BAFA4260189E94CAC8FB19F369A","ObjectName":"C:\\Windows\\readme.pdf","ObjectServer":"Security","ObjectType":"File","ProcessGuid":"{515cd0d1-2921-6152-721b-000000008200}","ProcessId":"0xD8C","ProcessName":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","ResourceAttributes":"S:AI","SubjectDomainName":"DESKTOP-LJRVE06","SubjectLogonId":"0x361D5","SubjectUserName":"Generic","SubjectUserSid":"S-1-5-21-2915380141-4195670196-3871645020-1001"},"System":{"Channel":"Security","Computer":"DESKTOP-LJRVE06","EventID":4663,"Execution":{"ProcessID":4,"ThreadID":7136},"Keywords":{"Value":9232379236109517000,"Name":""},"Level":{"Value":0,"Name":""},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Name":"Microsoft-Windows-Security-Auditing"},"TimeCreated":{"SystemTime":"2021-09-27T20:27:28.7685432Z"}},"Detection":{"Signature":["Builtin:CanaryAccessed"],"Criticality":10,"Actions":["kill","memdump","filedump","blacklist","report"]}}}`
	event := EdrEvent{}
	if err := json.Unmarshal([]byte(str), &event); err != nil {
		t.Error(err)
	}
	h := event.Hash()
	for i := 0; i < 10000; i++ {
		// testing hash stability
		tt.Assert(h == event.Hash())
	}
}

func TestEventHashStability(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)
	for event := range emitEvents(10000, true) {
		h := event.Hash()
		for i := 0; i < 100; i++ {
			tt.Assert(h == event.Hash())
		}
	}
}

func TestEventGetters(t *testing.T) {
	t.Parallel()
	str := `
	{
	"Event": {
		"EventData": {
		"Ancestors": "C:\\Windows\\System32\\services.exe",
		"CommandLine": "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /svc",
		"Company": "Google LLC",
		"CurrentDirectory": "C:\\Windows\\system32\\",
		"Description": "Google Installer",
		"FileVersion": "1.3.36.81",
		"Hashes": "SHA1=12950D906FF703F3A1E0BD973FCA2B433E5AB207,MD5=9A66A3DE2589F7108426AF37AB7F6B41,SHA256=A913415626433D5D0F07D3EC4084A67FF6F5138C3C3F64E36DD0C1AE4C423C65,IMPHASH=7DF1816239C5BC855600D41210406C5B",
		"Image": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
		"ImageSize": "154456",
		"IntegrityLevel": "System",
		"LogonGuid": "{515cd0d1-405a-6126-e703-000000000000}",
		"LogonId": "0x3E7",
		"OriginalFileName": "GoogleUpdate.exe",
		"ParentCommandLine": "C:\\Windows\\system32\\services.exe",
		"ParentImage": "C:\\Windows\\System32\\services.exe",
		"ParentIntegrityLevel": "?",
		"ParentProcessGuid": "{515cd0d1-405a-6126-0b00-000000008200}",
		"ParentProcessId": "688",
		"ParentServices": "?",
		"ParentUser": "?",
		"ProcessGuid": "{515cd0d1-322e-614e-9c12-000000008200}",
		"ProcessId": "1928",
		"Product": "Google Update",
		"RuleName": "-",
		"Services": "gupdate",
		"TerminalSessionId": "0",
		"User": "NT AUTHORITY\\SYSTEM",
		"UtcTime": "2021-09-24 20:16:46.328"
		},
		"System": {
		"Channel": "Microsoft-Windows-Sysmon/Operational",
		"Computer": "DESKTOP-LJRVE06",
		"EventID": 1,
		"Execution": {
			"ProcessID": 3296,
			"ThreadID": 2628
		},
		"Keywords": {
			"Value": 9223372036854776000,
			"Name": ""
		},
		"Level": {
			"Value": 4,
			"Name": "Information"
		},
		"Opcode": {
			"Value": 0,
			"Name": "Info"
		},
		"Task": {
			"Value": 0,
			"Name": ""
		},
		"Provider": {
			"Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
			"Name": "Microsoft-Windows-Sysmon"
		},
		"TimeCreated": {
			"SystemTime": "2021-08-28T14:49:40.20152Z"
		}
		},
		"EdrData": {
		"Endpoint": {
			"UUID": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
			"IP": "192.168.56.110",
			"Hostname": "DESKTOP-LJRVE06",
			"Group": "HR"
		},
		"Event": {
			"Hash": "e07dba161abdc26a7145b44019fb66ad6a6c26ed",
			"Detection": true,
			"ReceiptTime": "2021-09-24T20:16:47.84472107Z"
		}
		},
		"Detection": {
		"Signature": [
			"UnknownServices"
		],
		"Criticality": 10,
		"Actions": []
		}
	}
	}
	`
	tt := toast.FromT(t)
	event := EdrEvent{}

	tt.CheckErr(json.Unmarshal([]byte(str), &event))

	processId := engine.Path(eventData + "ProcessId")
	description := engine.Path(eventData + "Description")
	unknown := engine.Path(eventData + "Unknown")
	tt.CheckErr(event.SetIfOr(processId, "666", true, "1928"))
	tt.CheckErr(event.SetIfOr(processId, "666", false, "1928"))
	tt.CheckErr(event.SetIf(processId, "42", true))
	tt.CheckErr(event.SetIf(processId, "1928", true))
	tt.Assert(event.GetIntOr(processId, -1) == 1928)
	tt.Assert(event.GetIntOr(unknown, -1) == -1)
	tt.Assert(event.GetUintOr(processId, 0) == 1928)
	tt.Assert(event.GetUintOr(unknown, 0) == 0)
	tt.Assert(event.GetStringOr(description, "?") == "Google Installer")
	tt.Assert(event.GetStringOr(unknown, "?") == "?")

	// testing SetIfMissing
	// description is there so the attempt to set the value should fail
	tt.CheckErr(event.SetIfMissing(description, "?"))
	tt.Assert(event.GetStringOr(description, "?") == "Google Installer")
	// unknown is not set so it should set it
	tt.CheckErr(event.SetIfMissing(unknown, "unk"))
	tt.Assert(event.GetStringOr(unknown, "?") == "unk")

	// skip event
	tt.Assert(!event.IsSkipped())
	event.Skip()
	tt.Assert(event.IsSkipped())

	tt.Assert(event.Channel() == "Microsoft-Windows-Sysmon/Operational")
	tt.Assert(event.IsDetection())
	tt.Assert(event.GetDetection().Criticality == 10)
	event.SetDetection(nil)
	event.SetDetection(&engine.Detection{Criticality: 0})
	event.Event.Detection = nil
	tt.Assert(!event.IsDetection(), "Event should not be a detection")
	tt.Assert(event.Computer() == "DESKTOP-LJRVE06", "Wrong computer name")
	tt.Assert(event.EventID() == 1, "Wrong event ID")
	ts, _ := time.Parse(time.RFC3339Nano, "2021-08-28T14:49:40.20152Z")
	tt.Assert(event.Timestamp().Equal(ts), "Wrong timestamp")

	tt.Assert(event.Event.EdrData.Endpoint.Hostname == event.Computer(), "Wrong computer name")
	event.InitEdrData()
	tt.Assert(event.Event.EdrData.Endpoint.Hostname == "", "Computer name must be empty")
}
