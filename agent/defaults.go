package agent

import (
	"path/filepath"
	"time"

	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/api"
	clientConfig "github.com/0xrawsec/whids/api/client/config"
)

func BuildDefaultConfig(root string) *config.Agent {

	logDir := filepath.Join(root, "Logs")

	return &config.Agent{
		RulesConfig: &config.Rules{
			RulesDB:        filepath.Join(root, "Database", "Rules"),
			ContainersDB:   filepath.Join(root, "Database", "Containers"),
			UpdateInterval: 60 * time.Second,
		},

		FwdConfig: &clientConfig.Forwarder{
			Local: true,
			Client: clientConfig.Client{
				MaxUploadSize: api.DefaultMaxUploadSize,
			},
			Logging: clientConfig.ForwarderLogging{
				Dir:              filepath.Join(logDir, "Alerts"),
				RotationInterval: time.Hour * 5,
			},
		},
		EtwConfig: &config.Etw{
			Providers: []string{
				"Microsoft-Windows-Sysmon",
				"Microsoft-Windows-Windows Defender",
				"Microsoft-Windows-PowerShell",
				"Microsoft-Antimalware-Scan-Interface",
			},
			Traces: []string{"Eventlog-Security"},
		},
		Sysmon: &config.Sysmon{
			Bin:              "C:\\Windows\\Sysmon64.exe",
			ArchiveDirectory: "C:\\Sysmon\\",
			CleanArchived:    true,
		},
		Actions: &config.Actions{
			AvailableActions: AvailableActions,
			Low:              []string{},
			Medium:           []string{"brief", "filedump", "regdump"},
			High:             []string{"report", "filedump", "regdump"},
			Critical:         []string{"report", "filedump", "regdump", "memdump"},
		},
		Dump: &config.Dump{
			Dir:           filepath.Join(root, "Dumps"),
			Compression:   true,
			MaxDumps:      4,
			DumpUntracked: false,
		},
		Report: &config.Report{
			EnableReporting: false,
			OSQuery: config.OSQuery{
				Tables: []string{"processes", "services", "scheduled_tasks", "drivers", "startup_items", "process_open_sockets"}},
			Commands: []config.ReportCommand{{
				Description: "Example command",
				Name:        "osqueryi.exe",
				Args:        []string{"--json", "-A", "processes"},
				ExpectJSON:  true,
			}},
			CommandTimeout: 60 * time.Second,
		},
		AuditConfig: &config.Audit{
			AuditPolicies: []string{"File System"},
		},
		CanariesConfig: &config.Canaries{
			Enable: false,
			Canaries: []*config.Canary{
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
