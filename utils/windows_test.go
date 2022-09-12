//go:build windows
// +build windows

package utils

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/toast"
)

var (
	aclDirectories = []string{"C:\\Windows\\System32"}
)

func TestSetAuditACL(t *testing.T) {
	if err := SetEDRAuditACL(aclDirectories...); err != nil {
		t.Logf("Failed at setting Audit ACL: %s", err)
		t.FailNow()
	}
	t.Logf("Successfully set audit ACL")
}
func TestRemoveAuditACL(t *testing.T) {
	if err := RemoveEDRAuditACL(aclDirectories...); err != nil {
		t.Logf("Failed at setting Audit ACL: %s", err)
		t.FailNow()
	}
	t.Logf("Successfully set audit ACL")
}

func TestDisableFSAuditing(t *testing.T) {
	if err := DisableAuditPolicy("File System"); err != nil {
		t.Errorf("Failed at disabling FS Auditing: %s", err)
	}
}

func TestEnableFSAuditing(t *testing.T) {
	if err := EnableAuditPolicy("{0CCE921D-69AE-11D9-BED3-505054503030}"); err != nil {
		t.Errorf("Failed at enabling FS Auditing: %s", err)
	}
}

func TestRegValueToString(t *testing.T) {
	t.Parallel()

	pathBuildInfo := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\`
	pathSystemInfo := `HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation\`
	pathProcInfo := `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\`

	tt := toast.FromT(t)

	pn := RegValueToString(pathBuildInfo, "ProductName")
	t.Log(pn)
	tt.Assert(pn != "")

	bv := RegValueToString(pathSystemInfo, "BIOSVersion")
	t.Log(bv)
	tt.Assert(bv != "")

	cpu := RegValueToString(pathProcInfo, "0", "ProcessorNameString")
	t.Log(cpu)
	tt.Assert(cpu != "")
}

func TestResolveCDdrive(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	// we need to first call a bogus resolve
	ResolveCDrive("test")

	rawC := cDriveDeviceRe.String()
	// existing dirs from C:
	dirs := []string{"Windows", "Program Files", "Windows\\System32"}

	for _, d := range dirs {
		raw := filepath.Join(rawC, d)
		t.Logf("resolving %s", raw)
		tt.Assert(fsutil.IsDir(ResolveCDrive(raw)))
	}

	system32 := `Windows\System32\`
	// files available in system32
	files := []string{"cmd.exe", "conhost.exe", "wmi.dll", "advapi32.dll"}
	for _, f := range files {
		raw := filepath.Join(rawC, system32, f)
		t.Logf("resolving %s", raw)
		tt.Assert(fsutil.IsFile(ResolveCDrive(raw)))
	}
}

func TestHideFile(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	hidden := filepath.Join(t.TempDir(), "hidden.txt")
	tt.CheckErr(HidsWriteData(hidden, nil))
	visible := filepath.Join(t.TempDir(), "hidden.txt")
	tt.CheckErr(HidsWriteData(visible, nil))

	// testing hidden file
	tt.CheckErr(HideFile(hidden))
	attrs, err := GetFileAttributes(hidden)
	tt.CheckErr(err)
	tt.Assert(attrs&syscall.FILE_ATTRIBUTE_HIDDEN != 0)

	attrs, err = GetFileAttributes(visible)
	tt.CheckErr(err)
	tt.Assert(attrs&syscall.FILE_ATTRIBUTE_HIDDEN == 0)
}

func TestArgvFromCommandLine(t *testing.T) {
	t.Parallel()

	cmdLine := `%%SystemRoot%%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16`

	tt := toast.FromT(t)
	argv, err := ArgvFromCommandLine(cmdLine)
	tt.CheckErr(err)
	t.Log(JsonStringOrPanic(argv))
}
