package agent

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

// Microsoft-Windows-Kernel-File/Analytic
const (
	KernelFileNameCreate = iota + 10
	KernelFileNameDelete
	KernelFileCreate
	KernelFileCleanup
	KernelFileClose
	KernelFileRead
	KernelFileWrite
	KernelFileSetInformation
	KernelFileSetDelete
	KernelFileRename
	KernelFileDirEnum
	KernelFileFlush
	KernelFileQueryInformation
	KernelFileFSCTL
	KernelFileOperationEnd
	KernelFileDirNotify
	KernelFileDeletePath
	KernelFileRenamePath
	KernelFileSetLinkPath
	KernelFileCreateNewFile
	KernelFileSetSecurity
	KernelFileQuerySecurity
	KernelFileSetEA
	KernelFileQueryEA
)

var (
	KernelFileOperations = map[int64]string{
		KernelFileNameCreate:       "NameCreate",
		KernelFileNameDelete:       "NameDelete",
		KernelFileCreate:           "Create",
		KernelFileCleanup:          "Cleanup",
		KernelFileClose:            "Close",
		KernelFileRead:             "Read",
		KernelFileWrite:            "Write",
		KernelFileSetInformation:   "SetInformation",
		KernelFileSetDelete:        "SetDelete",
		KernelFileRename:           "Rename",
		KernelFileDirEnum:          "DirEnum",
		KernelFileFlush:            "Flush",
		KernelFileQueryInformation: "QueryInformation",
		KernelFileFSCTL:            "FSCTL",
		KernelFileOperationEnd:     "OperationEnd",
		KernelFileDirNotify:        "DirNotify",
		KernelFileDeletePath:       "DeletePath",
		KernelFileRenamePath:       "RenamePath",
		KernelFileSetLinkPath:      "SetLinkPath",
		KernelFileCreateNewFile:    "CreateNewFile",
		KernelFileSetSecurity:      "SetSecurity",
		KernelFileQuerySecurity:    "QuerySecurity",
		KernelFileSetEA:            "SetEA",
		KernelFileQueryEA:          "QueryEA",
	}
)
