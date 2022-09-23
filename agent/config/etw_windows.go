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
	EdrTraceClockTime   = 2   // System Time -> only way to handle time sync properly
	EdrTraceMaxFileSize = 500 // 500MB of ETW RT session backup file should be enough not to lose event

	KernelFileProviderName = "Microsoft-Windows-Kernel-File"
)

var (
	Autologger = etw.AutoLogger{
		Name:        EdrTraceName,
		Guid:        EdrTraceGuid,
		LogFileMode: EdrTraceLogFileMode,
		BufferSize:  EdrBufferSize,
		ClockType:   EdrTraceClockTime,
		MaxFileSize: EdrTraceMaxFileSize,
	}
)

func (e *Etw) optimizedKernelFileProvider() string {
	// create / close event ids
	eventIds := []string{"12", "14"}
	if e.TraceFiles.Read {
		eventIds = append(eventIds, "15")
	}
	if e.TraceFiles.Write {
		eventIds = append(eventIds, "16")
	}

	return fmt.Sprintf("%s:0xff:%s", KernelFileProviderName, strings.Join(eventIds, ","))
}

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
		// we don't take kernel file provider if we enabled tracing feature
		if strings.HasPrefix(p, KernelFileProviderName) && c.FileTraceEnabled() {
			continue
		}
		providers = append(providers, p)
	}

	if c.FileTraceEnabled() {
		// we append specific kernel file provider
		providers = append(providers, c.optimizedKernelFileProvider())
	}

	return utils.DedupStringSlice(providers)
}

func (c *Etw) UnifiedTraces() []string {
	return utils.DedupStringSlice(append(c.Traces, EdrTraceName))

}
