package hids

import (
	"path/filepath"
	"testing"

	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/utils"
)

const (
	system32 = `C:\Windows\System32`
)

func TestCmdHash(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	fi, err := cmdHash(`C:\Windows\System32\cmd.exe`)
	tt.CheckErr(err)
	tt.Assert(fi.Type == "file")
	t.Log(utils.PrettyJson(fi))
}

func TestCmdDir(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)
	dir := `C:\Windows\System32`
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
	fis, err := cmdFind(system32, `\\cmd\.exe$`, true)
	tt.CheckErr(err)
	tt.Assert(len(fis) > 0)
	for _, fi := range fis {
		tt.Assert(fi.Name == "cmd.exe")

	}
}

func TestCmdStat(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)
	st, err := cmdStat(filepath.Join(system32, "cmd.exe"))
	tt.CheckErr(err)
	tt.Assert(st.Name == "cmd.exe")
}
