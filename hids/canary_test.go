package hids

import (
	"runtime"
	"testing"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/toast"
)

var (
	canaryConfig = CanariesConfig{
		Enable:    true,
		Actions:   make([]string, 0),
		Whitelist: make([]string, 0),
		Canaries:  make([]*Canary, 0),
	}
)

func init() {
	switch runtime.GOOS {
	case "windows":
		canaryConfig.Canaries = append(canaryConfig.Canaries,
			&Canary{
				HideFiles:   true,
				Directories: []string{`C:\Windows\`, `C:\Windows\System32\`},
				Files:       []string{`readme.txt`, `readme.pdf`},
				Delete:      true,
			})
	default:
	}
}

func TestCanaries(t *testing.T) {
	tt := toast.FromT(t)
	e := engine.NewEngine()

	defer canaryConfig.Clean()
	defer canaryConfig.RestoreACLs()

	tt.CheckErr(canaryConfig.Configure())

	// checking that the files created have been well created
	for _, canary := range canaryConfig.Canaries {
		for _, file := range canary.paths() {
			tt.Assert(fsutil.Exists(file))
		}
	}

	tt.CheckErr(canaryConfig.Clean())
	rules := []engine.Rule{
		canaryConfig.GenRuleFSAudit(),
		canaryConfig.GenRuleKernelFile(),
		canaryConfig.GenRuleSysmon(),
	}

	for _, r := range rules {
		tt.CheckErr(e.LoadRule(&r))
	}

	// checking that files created got well deleted
	for _, canary := range canaryConfig.Canaries {
		for _, file := range canary.paths() {
			t.Logf("%s existing: %t", file, fsutil.Exists(file))
			tt.Assert(!fsutil.Exists(file))
		}
	}

	tt.CheckErr(canaryConfig.RestoreACLs())
}
