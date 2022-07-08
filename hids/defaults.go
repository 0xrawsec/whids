package hids

import (
	"path/filepath"
	"time"

	"github.com/0xrawsec/whids/api"
)

func BuildDefaultConfig(root string) *Config {

	logDir := filepath.Join(root, "Logs")

	return &Config{
		RulesConfig: &RulesConfig{
			RulesDB:        filepath.Join(root, "Database", "Rules"),
			ContainersDB:   filepath.Join(root, "Database", "Containers"),
			UpdateInterval: 60 * time.Second,
		},

		FwdConfig: &api.ForwarderConfig{
			Local: true,
			Client: api.ClientConfig{
				MaxUploadSize: api.DefaultMaxUploadSize,
			},
			Logging: api.LoggingConfig{
				Dir:              filepath.Join(logDir, "Alerts"),
				RotationInterval: time.Hour * 5,
			},
		},
		EtwConfig: &EtwConfig{
			Providers: []string{
				"Microsoft-Windows-Sysmon",
				"Microsoft-Windows-Windows Defender",
				"Microsoft-Windows-PowerShell",
				"Microsoft-Antimalware-Scan-Interface",
			},
			Traces: []string{"Eventlog-Security"},
		},
		Sysmon: &SysmonConfig{
			Bin:              "C:\\Windows\\Sysmon64.exe",
			ArchiveDirectory: "C:\\Sysmon\\",
			CleanArchived:    true,
		},
		Actions: &ActionsConfig{
			AvailableActions: AvailableActions,
			Low:              []string{},
			Medium:           []string{"brief", "filedump", "regdump"},
			High:             []string{"report", "filedump", "regdump"},
			Critical:         []string{"report", "filedump", "regdump", "memdump"},
		},
		Dump: &DumpConfig{
			Dir:           filepath.Join(root, "Dumps"),
			Compression:   true,
			MaxDumps:      4,
			DumpUntracked: false,
		},
		Report: &ReportConfig{
			EnableReporting: false,
			OSQuery: OSQueryConfig{
				Tables: []string{"processes", "services", "scheduled_tasks", "drivers", "startup_items", "process_open_sockets"}},
			Commands: []ReportCommand{{
				Description: "Example command",
				Name:        "osqueryi.exe",
				Args:        []string{"--json", "-A", "processes"},
				ExpectJSON:  true,
			}},
			CommandTimeout: 60 * time.Second,
		},
		AuditConfig: &AuditConfig{
			AuditPolicies: []string{"File System"},
		},
		CanariesConfig: &CanariesConfig{
			Enable: false,
			Canaries: []*Canary{
				{
					Directories: []string{"$SYSTEMDRIVE", "$SYSTEMROOT"},
					Files:       []string{"readme.pdf", "readme.docx", "readme.txt"},
					Delete:      true,
				},
			},
			Actions: []string{"kill", "memdump", "filedump", "blacklist", "report"},
			Whitelist: []string{
				"System",
				"C:\\Windows\\explorer.exe",
			},
		},
		CritTresh:       5,
		Logfile:         filepath.Join(logDir, "whids.log"),
		EnableHooks:     true,
		EnableFiltering: true,
		Endpoint:        true,
		LogAll:          false}
}
