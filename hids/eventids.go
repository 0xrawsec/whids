package hids

// Sysmon Event IDs
const (
	_ = iota
	SysmonProcessCreate
	SysmonFileTime
	SysmonNetworkConnect
	SysmonServiceStateChange
	SysmonProcessTerminate
	SysmonDriverLoad
	SysmonImageLoad
	SysmonCreateRemoteThread
	SysmonRawAccessRead
	SysmonAccessProcess
	SysmonFileCreate
	SysmonRegKey
	SysmonRegSetValue
	SysmonRegName
	SysmonCreateStreamHash
	SysmonServiceConfigurationChange
	SysmonCreateNamedPipe
	SysmonConnectNamedPipe
	SysmonWMIFilter
	SysmonWMIConsumer
	SysmonWMIBinding
	SysmonDNSQuery
	SysmonFileDelete
	SysmonClipboardChange
	SysmonProcessTampering
	SysmonFileDeleteDetected
)

const (
	// https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
	SecurityAccessObject = 4663
)
