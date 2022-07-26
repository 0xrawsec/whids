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
