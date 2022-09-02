//go:build windows
// +build windows

package config

import (
	"fmt"
	"strings"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/whids/utils"
)

const (
	/** Public const **/

	EdrTraceName        = `EdrTrace`
	EdrTraceGuid        = "{e32c0429-d46b-47a9-ab6c-074012efe5ba}"
	EdrBufferSize       = 64 // 64kB is the max ETW event size so the buffer needs to be at least this big
	EdrTraceLogFileMode = 0x8001c0
	EdrTraceClockTime   = 2 // System Time -> only way to handle time sync properly

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

func (c *Etw) ConfigureAutologger() (lastErr error) {

	if err := Autologger.Create(); err != nil {
		return fmt.Errorf("failed to create autologger: %w", err)
	}

	for _, p := range c.UnifiedProviders() {
		if prov, err := etw.ParseProvider(p); err != nil {
			lastErr = fmt.Errorf("failed to parse provider: %w", err)
		} else {
			if err := Autologger.EnableProvider(prov); err != nil {
				lastErr = fmt.Errorf("failed to enable provider: %w", err)
			}
		}
	}

	return
}

func (c *Etw) UnifiedProviders() (providers []string) {
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

	return utils.DedupStringSlice(providers)
}

func (c *Etw) UnifiedTraces() []string {
	return utils.DedupStringSlice(append(c.Traces, EdrTraceName))

}
