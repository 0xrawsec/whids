package hids

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/whids/event"
)

var (
	// DNSFilter filters any Windows-DNS-Client log
	DNSFilter = NewFilter([]int64{}, "Microsoft-Windows-DNS-Client/Operational")
	// SysmonNetConnFilter filters any Sysmon network connection
	SysmonNetConnFilter = NewFilter([]int64{3}, "Microsoft-Windows-Sysmon/Operational")
	eventSource         = "test/new-events.json"
	queryValue          = engine.Path("/Event/EventData/QueryName")
	queryType           = engine.Path("/Event/EventData/QueryType")
	queryResults        = engine.Path("/Event/EventData/QueryResults")
	destIP              = engine.Path("/Event/EventData/DestinationIp")
	destHostname        = engine.Path("/Event/EventData/DestinationHostname")
	dnsResolution       = make(map[string]string)
)

func hookDNS(h *HIDS, e *event.EdrEvent) {
	if qtype, ok := e.GetInt(queryType); ok {
		// request for A or AAAA records
		if qtype == 1 || qtype == 28 {
			if qresults, ok := e.GetString(queryResults); ok {
				if qresults != "" {
					records := strings.Split(qresults, ";")
					for _, r := range records {
						// check if it is a valid IP
						if net.ParseIP(r) != nil {
							if qv, ok := e.GetString(queryValue); ok {
								log.Infof("%s : %s", r, qv)
								dnsResolution[r] = qv
							}
						}
					}
				}
			}
		}
	}
}

func hookNetConn(h *HIDS, e *event.EdrEvent) {
	if ip, ok := e.GetString(destIP); ok {
		if dom, ok := dnsResolution[ip]; ok {
			e.Set(destHostname, dom)
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
		e := event.EdrEvent{}
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
