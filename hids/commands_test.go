package hids

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/utils"
)

var (
	testDir  string
	testFile string

	format = fmt.Sprintf
)

func init() {
	switch runtime.GOOS {
	case "windows":
		testDir = `C:\Windows\System32`
		testFile = "cmd.exe"
	default:
		testDir = "/usr/bin"
		testFile = "ls"
	}
}

func TestCmdHash(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	fi, err := cmdHash(filepath.Join(testDir, testFile))
	tt.CheckErr(err)
	tt.Assert(fi.Type == "file")
	t.Log(utils.PrettyJson(fi))
}

func TestCmdDir(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)
	dir := testDir
	d, err := cmdDir(dir)
	tt.CheckErr(err)
	for _, fi := range d {
		tt.Assert(fi.Dir == dir)
	}
	t.Log(utils.PrettyJson(d))
}

func TestCmdFind(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)
	rex := regexp.QuoteMeta(format("%c%s", filepath.Separator, testFile))
	fis, err := cmdFind(testDir, format(`%s$`, rex), true)
	tt.CheckErr(err)
	tt.Assert(len(fis) > 0)
	for _, fi := range fis {
		tt.Assert(fi.Name == testFile)

	}
}

func TestCmdStat(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)
	st, err := cmdStat(filepath.Join(testDir, testFile))
	tt.CheckErr(err)
	tt.Assert(st.Name == testFile)
}

func TestCmdWalk(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	items := cmdWalk(testDir)
	tt.Assert(len(items) > 0)
	for _, it := range items {
		tt.Assert(it.Err == "")
	}
}
