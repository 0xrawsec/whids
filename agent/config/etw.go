package config

type TraceFiles struct {
	Read  bool `json:"en-read" toml:"" comment:"Enable file write tracing events"`
	Write bool `json:"en-write" toml:"" comment:"Enable file read tracing events"`
}

type Etw struct {
	TraceFiles TraceFiles `json:"trace-files" toml:"trace-files" comment:"Enable file read/write events via an optimized Microsoft-Windows-Kernel-File provider"`
	//enTraceFile bool     `json:"trace-files" toml:"trace-files" comment:"Enable file read/write events via an optimized Microsoft-Windows-Kernel-File provider"`
	Providers []string `json:"providers" toml:"providers" comment:"ETW providers to enable in the EDR autologger setting"`
	Traces    []string `json:"traces" toml:"traces" comment:"Additional ETW traces to retrieve events"`
}

func (e *Etw) FileTraceEnabled() bool {
	return e.TraceFiles.Read || e.TraceFiles.Write
}
