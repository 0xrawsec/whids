package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/api/client/config"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/tools"
)

func buildDefaultConfig(root string) Agent {

	logDir := filepath.Join(root, "Logs")
	dbDir := filepath.Join(root, "Database")

	return Agent{
		DatabasePath: filepath.Join(dbDir, "Sod"),
		RulesConfig: Rules{
			RulesDB:        filepath.Join(dbDir, "Rules"),
			ContainersDB:   filepath.Join(dbDir, "Containers"),
			UpdateInterval: 60 * time.Second,
		},

		FwdConfig: config.Forwarder{
			Local:  true,
			Client: config.Client{},
			Logging: config.ForwarderLogging{
				Dir:              filepath.Join(logDir, "Alerts"),
				RotationInterval: time.Hour * 5,
			},
		},
		EtwConfig: Etw{
			Providers: []string{
				"Microsoft-Windows-Sysmon",
				"Microsoft-Windows-Windows Defender",
				"Microsoft-Windows-PowerShell",
				"Microsoft-Antimalware-Scan-Interface",
			},
			Traces: []string{"Eventlog-Security"},
		},
		Sysmon: Sysmon{
			Bin:              "C:\\Windows\\Sysmon64.exe",
			ArchiveDirectory: "C:\\Sysmon\\",
			CleanArchived:    true,
		},
		Actions: Actions{
			Low:      []string{},
			Medium:   []string{"brief", "filedump", "regdump"},
			High:     []string{"report", "filedump", "regdump"},
			Critical: []string{"report", "filedump", "regdump", "memdump"},
		},
		Dump: Dump{
			Dir:           filepath.Join(root, "Dumps"),
			Compression:   true,
			MaxDumps:      4,
			DumpUntracked: false,
		},
		Report: Report{
			EnableReporting: false,
			OSQuery: OSQuery{
				Tables: []string{"processes", "services", "scheduled_tasks", "drivers", "startup_items", "process_open_sockets"}},
			Commands: []ReportCommand{{
				Description: "Example command",
				Name:        "osqueryi.exe",
				Args:        []string{"--json", "-A", "processes"},
				ExpectJSON:  true,
			}},
			CommandTimeout: 60 * time.Second,
		},
		AuditConfig: Audit{
			AuditPolicies: []string{"File System"},
		},
		CanariesConfig: Canaries{
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

func TestConfig(t *testing.T) {
	var err error
	var sha256, savedSha256 string

	t.Parallel()

	tt := toast.FromT(t)
	tmp := t.TempDir()

	cfg := buildDefaultConfig(tmp)
	path := filepath.Join(tmp, "config.toml")

	pathRules, pathSha256 := cfg.RulesConfig.RulesPaths()
	tt.Assert(pathRules == filepath.Join(cfg.RulesConfig.RulesDB, "database.gen"))
	tt.Assert(pathSha256 == filepath.Join(cfg.RulesConfig.RulesDB, "database.gen.sha256"))

	// testing IsForwardingEnabled
	tt.Assert(cfg.IsForwardingEnabled() == false)
	cfg.FwdConfig.Local = false
	tt.Assert(cfg.IsForwardingEnabled() == false)
	cfg.FwdConfig.Client = config.Client{
		Proto: "http",
		Host:  "localhost",
		UUID:  "{0000}",
		Key:   "key",
	}
	tt.Assert(cfg.IsForwardingEnabled())

	// test hash stability of Save function
	sha256, err = cfg.Sha256()
	tt.CheckErr(err)
	tt.CheckErr(cfg.Save(path))
	cfg, err = LoadAgentConfig(path)
	tt.CheckErr(err)
	tt.Assert(cfg.Path() == path)
	// testing that sha256 did not get modified
	savedSha256, err = cfg.Sha256()
	tt.CheckErr(err)
	tt.Assert(sha256 == savedSha256)

	// test Prepare and Verify
	tt.CheckErr(cfg.Prepare())
	tt.CheckErr(cfg.Verify())

	goodProvLen := len(cfg.EtwConfig.Providers)
	// if there is no duplicate it should be the same number
	tt.Assert(len(cfg.EtwConfig.UnifiedProviders()) == goodProvLen)
	cfg.EtwConfig.Providers = append(cfg.EtwConfig.Providers, cfg.EtwConfig.Providers...)
	tt.Assert(len(cfg.EtwConfig.Providers) == goodProvLen*2)
	// should get rid of duplicates
	tt.Assert(len(cfg.EtwConfig.UnifiedProviders()) == goodProvLen)

	goodTracesLen := len(cfg.EtwConfig.Traces) + 1
	// should always be one more than configured because of EdrTrace always present
	tt.Assert(len(cfg.EtwConfig.UnifiedTraces()) == goodTracesLen)
	cfg.EtwConfig.Traces = append(cfg.EtwConfig.Traces, cfg.EtwConfig.Traces...)
	tt.Assert(len(cfg.EtwConfig.UnifiedTraces()) == goodTracesLen)
}

func TestReporting(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp := t.TempDir()
	cfg := buildDefaultConfig(tmp)
	// copy osquery binary
	src := fmt.Sprintf("../data/%s.%s%s", los.OS, tools.ToolOSQueryi, los.ExecExt)
	dst := los.ExecFilename(tools.ToolOSQueryi)
	tt.CheckErr(fsutil.CopyFile(src, dst))
	os.Setenv(los.PathEnvVar, los.BuildPathEnv(los.GetPathEnv(), tmp))

	for _, cmd := range cfg.Report.PrepareCommands() {
		cmd.Run()
		tt.Assert(cmd.Error == "", cmd.Error)
	}
}
