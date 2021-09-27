package event

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/whids/utils"
)

var (
	eventFile = "./data/events.json"
	events    = make([]EdrEvent, 0)
)

const (
	day   = time.Hour * 24
	month = day * 30
)

func init() {
	data, err := ioutil.ReadFile(eventFile)
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
	str := `{"Event":{"EventData":{"AccessList":"%%4416\r\n\t\t\t\t","AccessMask":"0x1","CommandLine":"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" ","HandleId":"0x1350","ImageHashes":"SHA1=957004ABEEF46EF5B5365F668F26868434E4D040,MD5=74859601FB4BEEA84B40D874CCB56CAB,SHA256=A35C86CCD3E26316C45A0E63EFA9CDD1E9D3B01B23F7829EAD9106FA5340066D,IMPHASH=891D2BAFA4260189E94CAC8FB19F369A","ObjectName":"C:\\Windows\\readme.pdf","ObjectServer":"Security","ObjectType":"File","ProcessGuid":"{515cd0d1-2921-6152-721b-000000008200}","ProcessId":"0xD8C","ProcessName":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","ResourceAttributes":"S:AI","SubjectDomainName":"DESKTOP-LJRVE06","SubjectLogonId":"0x361D5","SubjectUserName":"Generic","SubjectUserSid":"S-1-5-21-2915380141-4195670196-3871645020-1001"},"System":{"Channel":"Security","Computer":"DESKTOP-LJRVE06","EventID":4663,"Execution":{"ProcessID":4,"ThreadID":7136},"Keywords":{"Value":9232379236109517000,"Name":""},"Level":{"Value":0,"Name":""},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Name":"Microsoft-Windows-Security-Auditing"},"TimeCreated":{"SystemTime":"2021-09-27T20:27:28.7685432Z"}},"Detection":{"Signature":["Builtin:CanaryAccessed"],"Criticality":10,"Actions":["kill","memdump","filedump","blacklist","report"]}}}`
	event := EdrEvent{}
	if err := json.Unmarshal([]byte(str), &event); err != nil {
		t.Error(err)
	}
	h := event.Hash()
	for i := 0; i < 10000; i++ {
		if h != event.Hash() {
			t.Errorf("Event hashing function is not stable %s vs %s", h, event.Hash())
		}
	}
}

func TestEventHashStability(t *testing.T) {
	for event := range emitEvents(10000, true) {
		h := event.Hash()
		b1 := utils.Json(event)
		for i := 0; i < 100; i++ {
			if h != event.Hash() {
				b2 := utils.Json(event)
				t.Errorf("Event hashing function is not stable %s vs %s", h, event.Hash())
				t.Error(string(b1))
				t.Error(string(b2))
				//t.Error(utils.PrettyJson(event))
				break
			}
		}
	}

}
