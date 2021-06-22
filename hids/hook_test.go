package hids

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
)

var (
	// DNSFilter filters any Windows-DNS-Client log
	DNSFilter = NewFilter([]int64{}, "Microsoft-Windows-DNS-Client/Operational")
	// SysmonNetConnFilter filters any Sysmon network connection
	SysmonNetConnFilter = NewFilter([]int64{3}, "Microsoft-Windows-Sysmon/Operational")
	eventSource         = "test/new-events.json"
	queryValue          = evtx.Path("/Event/EventData/QueryName")
	queryType           = evtx.Path("/Event/EventData/QueryType")
	queryResults        = evtx.Path("/Event/EventData/QueryResults")
	destIP              = evtx.Path("/Event/EventData/DestinationIp")
	destHostname        = evtx.Path("/Event/EventData/DestinationHostname")
	dnsResolution       = make(map[string]string)
)

func hookDNS(h *HIDS, e *evtx.GoEvtxMap) {
	if qtype, err := e.GetInt(&queryType); err == nil {
		// request for A or AAAA records
		if qtype == 1 || qtype == 28 {
			if qresults, err := e.GetString(&queryResults); err == nil {
				if qresults != "" {
					records := strings.Split(qresults, ";")
					for _, r := range records {
						// check if it is a valid IP
						if net.ParseIP(r) != nil {
							log.Infof("%s : %s", r, e.GetStringStrict(&queryValue))
							dnsResolution[r] = e.GetStringStrict(&queryValue)
						}
					}
				}
			}
		}
	}
}

func hookNetConn(h *HIDS, e *evtx.GoEvtxMap) {
	if ip, err := e.GetString(&destIP); err == nil {
		if dom, ok := dnsResolution[ip]; ok {
			e.Set(&destHostname, dom)
		}
	}
}

func TestHook(t *testing.T) {
	hm := NewHookMan()
	hm.Hook(hookDNS, DNSFilter)
	hm.Hook(hookNetConn, SysmonNetConnFilter)
	f, err := os.Open(eventSource)
	if err != nil {
		t.Logf("Cannot open file: %s", eventSource)
		t.Fail()
		return
	}
	for line := range readers.Readlines(f) {
		e := evtx.GoEvtxMap{}
		err := json.Unmarshal(line, &e)
		if err != nil {
			t.Logf("JSON deserialization issue")
			t.Fail()
		}
		if hm.RunHooksOn(nil, &e) {
			t.Log(string(evtx.ToJSON(e)))
		}
	}
}
