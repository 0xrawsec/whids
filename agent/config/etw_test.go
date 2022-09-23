//go:build windows
// +build windows

package config

import (
	"testing"

	"github.com/0xrawsec/toast"
)

func TestEtwConfiguration(t *testing.T) {
	tt := toast.FromT(t)

	Autologger.Delete()
	defer Autologger.Delete()
	tt.Assert(!Autologger.Exists())

	c := Etw{
		Providers: []string{
			"Microsoft-Windows-Windows Defender",
			"Microsoft-Windows-PowerShell",
			"Microsoft-Antimalware-Scan-Interface",
		},
		Traces: []string{"Eventlog-Security"},
	}

	tt.CheckErr(c.ConfigureAutologger())
	tt.Assert(Autologger.Exists())
}

func TestEtwTraceFiles(t *testing.T) {
	tt := toast.FromT(t)

	c := Etw{
		Providers: []string{
			"Microsoft-Windows-Windows Defender",
			"Microsoft-Windows-PowerShell",
			"Microsoft-Antimalware-Scan-Interface",
		},
		Traces: []string{"Eventlog-Security"},
	}

	tt.Assert(!c.FileTraceEnabled())

	// only read
	c.TraceFiles.Read = true
	tt.Assert(c.FileTraceEnabled())
	tt.Assert(c.optimizedKernelFileProvider() == KernelFileProviderName+":0xff:12,14,15")

	// only write
	c.TraceFiles.Read = false
	c.TraceFiles.Write = true
	tt.Assert(c.FileTraceEnabled())
	tt.Assert(c.optimizedKernelFileProvider() == KernelFileProviderName+":0xff:12,14,16")

	// both read and write
	tt.Assert(c.FileTraceEnabled())
	c.TraceFiles.Read = true
	tt.Assert(c.optimizedKernelFileProvider() == KernelFileProviderName+":0xff:12,14,15,16")
}
