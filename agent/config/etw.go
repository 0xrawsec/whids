package config

type Etw struct {
	// set as private not to support it officially as Microsoft-Windows-Kernel-File generates too many events
	enTraceFile bool     `toml:"trace-files" comment:"Enable file read/write events via an optimized Microsoft-Windows-Kernel-File provider"`
	Providers   []string `toml:"providers" comment:"ETW providers to enable in the EDR autologger setting"`
	Traces      []string `toml:"traces" comment:"Additional ETW traces to retrieve events"`
}
