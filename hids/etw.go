package hids

import (
	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/golang-utils/datastructs"
)

const (
	/** Public const **/

	EdrTraceName        = `EdrTrace`
	EdrTraceGuid        = "{e32c0429-d46b-47a9-ab6c-074012efe5ba}"
	EdrTraceLogFileMode = 0x8001c0
)

var (
	Autologger = etw.AutoLogger{
		Name:        EdrTraceName,
		Guid:        EdrTraceGuid,
		LogFileMode: EdrTraceLogFileMode,
	}
)

type EtwConfig struct {
	Providers []string `toml:"providers" comment:"ETW providers to enable in the EDR autologger setting"`
	Traces    []string `toml:"traces" comment:"Additional ETW traces to retrieve events"`
}

func (c *EtwConfig) ConfigureAutologger() (lastErr error) {

	if err := Autologger.Create(); err != nil {
		return err
	}

	availProv := etw.EnumerateProviders()

	for _, p := range c.Providers {

		if g, err := etw.GUIDFromString(p); err == nil {
			p = g.String()
		} else if prov, ok := availProv[p]; ok {
			// search provider by name
			p = prov.GUID
		}

		if err := Autologger.EnableProvider(p, 0, 255); err != nil {
			lastErr = err
		}
	}

	return
}

func (c *EtwConfig) UnifiedTraces() []string {
	traces := make([]string, 0, len(c.Traces))
	marked := datastructs.NewSet()
	// adding EDR default trace
	traces = append(traces, EdrTraceName)
	marked.Add(EdrTraceName)
	for _, t := range c.Traces {
		if !marked.Contains(t) {
			traces = append(traces, t)
			marked.Add(t)
		}
	}
	return traces
}
