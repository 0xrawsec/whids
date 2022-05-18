//go:build windows
// +build windows

package sysinfo

import (
	"fmt"
	"strings"

	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/sysmon"
	"github.com/0xrawsec/whids/utils"
)

const (
	pathBuildInfo  = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\`
	pathSystemInfo = `HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation\`
	pathProcInfo   = `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\`
	pathHotFixes   = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\`
)

var (
	version = fmt.Sprintf("%s.%s.%s",
		utils.RegValueToString(pathBuildInfo, "CurrentMajorVersionNumber"),
		utils.RegValueToString(pathBuildInfo, "CurrentMinorVersionNumber"),
		utils.RegValueToString(pathBuildInfo, "CurrentBuild"),
	)
)

func NewSystemInfo() (info *SystemInfo) {
	info = &SystemInfo{
		Edr: edrInfo,
	}

	info.System.Manufacturer = utils.RegValueToString(pathSystemInfo, "SystemManufacturer")
	info.System.Name = utils.RegValueToString(pathSystemInfo, "SystemProductName")
	// cheap VM detection
	name := strings.ToLower(info.System.Name)
	lowManuf := strings.ToLower(info.System.Manufacturer)
	info.System.Virtual = strings.Contains(name, "virtual") || strings.Contains(lowManuf, "vmware")

	info.BIOS.Version = utils.RegValueToString(pathSystemInfo, "BIOSVersion")
	info.BIOS.Date = utils.RegValueToString(pathSystemInfo, "BIOSReleaseDate")

	info.OS.Name = los.OS
	info.OS.Build = utils.RegValueToString(pathBuildInfo, "CurrentBuild")
	info.OS.Version = version
	info.OS.Product = utils.RegValueToString(pathBuildInfo, "ProductName")
	info.OS.Edition = utils.RegValueToString(pathBuildInfo, "CompositionEditionID")

	info.CPU.Name = utils.RegValueToString(pathProcInfo, "0", "ProcessorNameString")
	// counting the number of processors
	procs, _ := advapi32.RegEnumKeys(pathProcInfo)
	info.CPU.Count = len(procs)

	info.Sysmon = sysmon.NewSysmonInfo()
	return
}
