package sysinfo

import "github.com/0xrawsec/whids/sysmon"

var (
	// must be set by main package
	edrInfo *EdrInfo
)

type EdrInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

func RegisterEdrInfo(i *EdrInfo) {
	edrInfo = i
}

type SystemInfo struct {
	Edr *EdrInfo `json:"edr"`

	System struct {
		// HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SystemInformation
		//SystemManufacturer
		Manufacturer string `json:"manufacturer"`
		//SystemProductName
		Name    string `json:"name"`
		Virtual bool   `json:"virtual"`
	} `json:"system"`

	BIOS struct {
		// HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SystemInformation
		//BIOSVersion
		Version string `json:"version"`
		//BIOSReleaseDate
		Date string `json:"date"`
	} `json:"bios"`

	OS struct {
		Name string `json:"name"`
		//HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
		// CurrentBuild
		Build string `json:"build"`
		// DisplayVersion + CurrentMajorVersionNumber + CurrentMinorVersionNumber + CurrentBuild
		Version string `json:"version"`
		// ProductName
		Product string `json:"product"`
		// CompositionEditionID
		Edition string `json:"edition"`
	} `json:"os"`

	CPU struct {
		// KEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0
		// ProcessorNameString
		Name  string `json:"name"`
		Count int    `json:"count"`
	} `json:"cpu"`

	Sysmon *sysmon.Info `json:"sysmon"`

	Err error `json:"error"`
}
