package agent

import (
	"time"

	"github.com/0xrawsec/whids/agent/config"
)

// Report structure
type Report struct {
	Processes map[string]ProcessTrack `json:"processes"`
	Modules   []ModuleInfo            `json:"modules"`
	Drivers   []DriverInfo            `json:"drivers"`
	Commands  []config.ReportCommand  `json:"commands"`
	StartTime time.Time               `json:"start-timestamp"` // time at which report generation started
	StopTime  time.Time               `json:"stop-timestamp"`  // time at which report generation stopped
}
