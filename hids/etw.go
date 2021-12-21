package hids

import (
	"strings"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/golang-utils/datastructs"
)

const (
	/** Public const **/

	EdrTraceName           = `EdrTrace`
	EdrTraceGuid           = "{e32c0429-d46b-47a9-ab6c-074012efe5ba}"
	EdrBufferSize          = 64 // 64kB is the max ETW event size so the buffer needs to be at least this big
	EdrTraceLogFileMode    = 0x8001c0
	EdrTraceClockTime      = 2 // System Time -> only way to handle time sync
	KernelFileProviderName = "Microsoft-Windows-Kernel-File"
	KernelFileProvider     = KernelFileProviderName + ":0xff:12,14,15,16"
)

var (
	Autologger = etw.AutoLogger{
		Name:        EdrTraceName,
		Guid:        EdrTraceGuid,
		LogFileMode: EdrTraceLogFileMode,
		BufferSize:  EdrBufferSize,
		ClockType:   EdrTraceClockTime,
	}
)

type EtwConfig struct {
	// set as private not to support it officially as Microsoft-Windows-Kernel-File generates too many events
	enTraceFile bool     `toml:"trace-files" comment:"Enable file read/write events via an optimized Microsoft-Windows-Kernel-File provider"`
	Providers   []string `toml:"providers" comment:"ETW providers to enable in the EDR autologger setting"`
	Traces      []string `toml:"traces" comment:"Additional ETW traces to retrieve events"`
}

func (c *EtwConfig) ConfigureAutologger() (lastErr error) {

	if err := Autologger.Create(); err != nil {
		return err
	}

	for _, p := range c.UnifiedProviders() {
		if prov, err := etw.ProviderFromString(p); err != nil {
			lastErr = err
		} else {
			if err := Autologger.EnableProvider(prov); err != nil {
				lastErr = err
			}
		}
	}

	return
}

func (c *EtwConfig) UnifiedProviders() (providers []string) {
	providers = make([]string, 0, len(c.Providers))
	for _, p := range c.Providers {
		if strings.HasPrefix(p, KernelFileProviderName) && c.enTraceFile {
			continue
		}
		providers = append(providers, p)
	}
	if c.enTraceFile {
		providers = append(providers, KernelFileProvider)
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
