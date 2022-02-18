package sysmon

/*
   This file has been auto-generated, do not edit it directly
   as it may be overwritten in the future
*/

var (
	Conditions = []string{
		"is",
		"is not",
		"contains",
		"contains any",
		"is any",
		"contains all",
		"excludes",
		"excludes any",
		"excludes all",
		"begin with",
		"not begin with",
		"end with",
		"not end with",
		"less than",
		"more than",
		"image",
	}
)

type ProcessCreate struct {
	EventFilter
	RuleName          []Filter `json:",omitempty"`
	UtcTime           []Filter `json:",omitempty"`
	ProcessGuid       []Filter `json:",omitempty"`
	ProcessId         []Filter `json:",omitempty"`
	Image             []Filter `json:",omitempty"`
	FileVersion       []Filter `json:",omitempty"`
	Description       []Filter `json:",omitempty"`
	Product           []Filter `json:",omitempty"`
	Company           []Filter `json:",omitempty"`
	OriginalFileName  []Filter `json:",omitempty"`
	CommandLine       []Filter `json:",omitempty"`
	CurrentDirectory  []Filter `json:",omitempty"`
	User              []Filter `json:",omitempty"`
	LogonGuid         []Filter `json:",omitempty"`
	LogonId           []Filter `json:",omitempty"`
	TerminalSessionId []Filter `json:",omitempty"`
	IntegrityLevel    []Filter `json:",omitempty"`
	Hashes            []Filter `json:",omitempty"`
	ParentProcessGuid []Filter `json:",omitempty"`
	ParentProcessId   []Filter `json:",omitempty"`
	ParentImage       []Filter `json:",omitempty"`
	ParentCommandLine []Filter `json:",omitempty"`
}

type FileCreateTime struct {
	EventFilter
	RuleName                []Filter `json:",omitempty"`
	UtcTime                 []Filter `json:",omitempty"`
	ProcessGuid             []Filter `json:",omitempty"`
	ProcessId               []Filter `json:",omitempty"`
	Image                   []Filter `json:",omitempty"`
	TargetFilename          []Filter `json:",omitempty"`
	CreationUtcTime         []Filter `json:",omitempty"`
	PreviousCreationUtcTime []Filter `json:",omitempty"`
}

type NetworkConnect struct {
	EventFilter
	RuleName            []Filter `json:",omitempty"`
	UtcTime             []Filter `json:",omitempty"`
	ProcessGuid         []Filter `json:",omitempty"`
	ProcessId           []Filter `json:",omitempty"`
	Image               []Filter `json:",omitempty"`
	User                []Filter `json:",omitempty"`
	Protocol            []Filter `json:",omitempty"`
	Initiated           []Filter `json:",omitempty"`
	SourceIsIpv6        []Filter `json:",omitempty"`
	SourceIp            []Filter `json:",omitempty"`
	SourceHostname      []Filter `json:",omitempty"`
	SourcePort          []Filter `json:",omitempty"`
	SourcePortName      []Filter `json:",omitempty"`
	DestinationIsIpv6   []Filter `json:",omitempty"`
	DestinationIp       []Filter `json:",omitempty"`
	DestinationHostname []Filter `json:",omitempty"`
	DestinationPort     []Filter `json:",omitempty"`
	DestinationPortName []Filter `json:",omitempty"`
}

type ProcessTerminate struct {
	EventFilter
	RuleName    []Filter `json:",omitempty"`
	UtcTime     []Filter `json:",omitempty"`
	ProcessGuid []Filter `json:",omitempty"`
	ProcessId   []Filter `json:",omitempty"`
	Image       []Filter `json:",omitempty"`
}

type DriverLoad struct {
	EventFilter
	RuleName        []Filter `json:",omitempty"`
	UtcTime         []Filter `json:",omitempty"`
	ImageLoaded     []Filter `json:",omitempty"`
	Hashes          []Filter `json:",omitempty"`
	Signed          []Filter `json:",omitempty"`
	Signature       []Filter `json:",omitempty"`
	SignatureStatus []Filter `json:",omitempty"`
}

type ImageLoad struct {
	EventFilter
	RuleName         []Filter `json:",omitempty"`
	UtcTime          []Filter `json:",omitempty"`
	ProcessGuid      []Filter `json:",omitempty"`
	ProcessId        []Filter `json:",omitempty"`
	Image            []Filter `json:",omitempty"`
	ImageLoaded      []Filter `json:",omitempty"`
	FileVersion      []Filter `json:",omitempty"`
	Description      []Filter `json:",omitempty"`
	Product          []Filter `json:",omitempty"`
	Company          []Filter `json:",omitempty"`
	OriginalFileName []Filter `json:",omitempty"`
	Hashes           []Filter `json:",omitempty"`
	Signed           []Filter `json:",omitempty"`
	Signature        []Filter `json:",omitempty"`
	SignatureStatus  []Filter `json:",omitempty"`
}

type CreateRemoteThread struct {
	EventFilter
	RuleName          []Filter `json:",omitempty"`
	UtcTime           []Filter `json:",omitempty"`
	SourceProcessGuid []Filter `json:",omitempty"`
	SourceProcessId   []Filter `json:",omitempty"`
	SourceImage       []Filter `json:",omitempty"`
	TargetProcessGuid []Filter `json:",omitempty"`
	TargetProcessId   []Filter `json:",omitempty"`
	TargetImage       []Filter `json:",omitempty"`
	NewThreadId       []Filter `json:",omitempty"`
	StartAddress      []Filter `json:",omitempty"`
	StartModule       []Filter `json:",omitempty"`
	StartFunction     []Filter `json:",omitempty"`
}

type RawAccessRead struct {
	EventFilter
	RuleName    []Filter `json:",omitempty"`
	UtcTime     []Filter `json:",omitempty"`
	ProcessGuid []Filter `json:",omitempty"`
	ProcessId   []Filter `json:",omitempty"`
	Image       []Filter `json:",omitempty"`
	Device      []Filter `json:",omitempty"`
}

type ProcessAccess struct {
	EventFilter
	RuleName          []Filter `json:",omitempty"`
	UtcTime           []Filter `json:",omitempty"`
	SourceProcessGUID []Filter `json:",omitempty"`
	SourceProcessId   []Filter `json:",omitempty"`
	SourceThreadId    []Filter `json:",omitempty"`
	SourceImage       []Filter `json:",omitempty"`
	TargetProcessGUID []Filter `json:",omitempty"`
	TargetProcessId   []Filter `json:",omitempty"`
	TargetImage       []Filter `json:",omitempty"`
	GrantedAccess     []Filter `json:",omitempty"`
	CallTrace         []Filter `json:",omitempty"`
}

type FileCreate struct {
	EventFilter
	RuleName        []Filter `json:",omitempty"`
	UtcTime         []Filter `json:",omitempty"`
	ProcessGuid     []Filter `json:",omitempty"`
	ProcessId       []Filter `json:",omitempty"`
	Image           []Filter `json:",omitempty"`
	TargetFilename  []Filter `json:",omitempty"`
	CreationUtcTime []Filter `json:",omitempty"`
}

type RegistryEvent struct {
	EventFilter
	RuleName     []Filter `json:",omitempty"`
	EventType    []Filter `json:",omitempty"`
	UtcTime      []Filter `json:",omitempty"`
	ProcessGuid  []Filter `json:",omitempty"`
	ProcessId    []Filter `json:",omitempty"`
	Image        []Filter `json:",omitempty"`
	TargetObject []Filter `json:",omitempty"`
}

type FileCreateStreamHash struct {
	EventFilter
	RuleName        []Filter `json:",omitempty"`
	UtcTime         []Filter `json:",omitempty"`
	ProcessGuid     []Filter `json:",omitempty"`
	ProcessId       []Filter `json:",omitempty"`
	Image           []Filter `json:",omitempty"`
	TargetFilename  []Filter `json:",omitempty"`
	CreationUtcTime []Filter `json:",omitempty"`
	Hash            []Filter `json:",omitempty"`
	Contents        []Filter `json:",omitempty"`
}

type PipeEvent struct {
	EventFilter
	RuleName    []Filter `json:",omitempty"`
	EventType   []Filter `json:",omitempty"`
	UtcTime     []Filter `json:",omitempty"`
	ProcessGuid []Filter `json:",omitempty"`
	ProcessId   []Filter `json:",omitempty"`
	PipeName    []Filter `json:",omitempty"`
	Image       []Filter `json:",omitempty"`
}

type WmiEvent struct {
	EventFilter
	RuleName       []Filter `json:",omitempty"`
	EventType      []Filter `json:",omitempty"`
	UtcTime        []Filter `json:",omitempty"`
	Operation      []Filter `json:",omitempty"`
	User           []Filter `json:",omitempty"`
	EventNamespace []Filter `json:",omitempty"`
	Name           []Filter `json:",omitempty"`
	Query          []Filter `json:",omitempty"`
}

type DnsQuery struct {
	EventFilter
	RuleName     []Filter `json:",omitempty"`
	UtcTime      []Filter `json:",omitempty"`
	ProcessGuid  []Filter `json:",omitempty"`
	ProcessId    []Filter `json:",omitempty"`
	QueryName    []Filter `json:",omitempty"`
	QueryStatus  []Filter `json:",omitempty"`
	QueryResults []Filter `json:",omitempty"`
	Image        []Filter `json:",omitempty"`
}

type FileDelete struct {
	EventFilter
	RuleName       []Filter `json:",omitempty"`
	UtcTime        []Filter `json:",omitempty"`
	ProcessGuid    []Filter `json:",omitempty"`
	ProcessId      []Filter `json:",omitempty"`
	User           []Filter `json:",omitempty"`
	Image          []Filter `json:",omitempty"`
	TargetFilename []Filter `json:",omitempty"`
	Hashes         []Filter `json:",omitempty"`
	IsExecutable   []Filter `json:",omitempty"`
	Archived       []Filter `json:",omitempty"`
}

type ClipboardChange struct {
	EventFilter
	RuleName    []Filter `json:",omitempty"`
	UtcTime     []Filter `json:",omitempty"`
	ProcessGuid []Filter `json:",omitempty"`
	ProcessId   []Filter `json:",omitempty"`
	Image       []Filter `json:",omitempty"`
	Session     []Filter `json:",omitempty"`
	ClientInfo  []Filter `json:",omitempty"`
	Hashes      []Filter `json:",omitempty"`
	Archived    []Filter `json:",omitempty"`
}

type ProcessTampering struct {
	EventFilter
	RuleName    []Filter `json:",omitempty"`
	UtcTime     []Filter `json:",omitempty"`
	ProcessGuid []Filter `json:",omitempty"`
	ProcessId   []Filter `json:",omitempty"`
	Image       []Filter `json:",omitempty"`
	Type        []Filter `json:",omitempty"`
}

type FileDeleteDetected struct {
	EventFilter
	RuleName       []Filter `json:",omitempty"`
	UtcTime        []Filter `json:",omitempty"`
	ProcessGuid    []Filter `json:",omitempty"`
	ProcessId      []Filter `json:",omitempty"`
	User           []Filter `json:",omitempty"`
	Image          []Filter `json:",omitempty"`
	TargetFilename []Filter `json:",omitempty"`
	Hashes         []Filter `json:",omitempty"`
	IsExecutable   []Filter `json:",omitempty"`
}

type Filters struct {
	ProcessCreate        *ProcessCreate        `xml:",omitempty" json:",omitempty"`
	FileCreateTime       *FileCreateTime       `xml:",omitempty" json:",omitempty"`
	NetworkConnect       *NetworkConnect       `xml:",omitempty" json:",omitempty"`
	ProcessTerminate     *ProcessTerminate     `xml:",omitempty" json:",omitempty"`
	DriverLoad           *DriverLoad           `xml:",omitempty" json:",omitempty"`
	ImageLoad            *ImageLoad            `xml:",omitempty" json:",omitempty"`
	CreateRemoteThread   *CreateRemoteThread   `xml:",omitempty" json:",omitempty"`
	RawAccessRead        *RawAccessRead        `xml:",omitempty" json:",omitempty"`
	ProcessAccess        *ProcessAccess        `xml:",omitempty" json:",omitempty"`
	FileCreate           *FileCreate           `xml:",omitempty" json:",omitempty"`
	RegistryEvent        *RegistryEvent        `xml:",omitempty" json:",omitempty"`
	FileCreateStreamHash *FileCreateStreamHash `xml:",omitempty" json:",omitempty"`
	PipeEvent            *PipeEvent            `xml:",omitempty" json:",omitempty"`
	WmiEvent             *WmiEvent             `xml:",omitempty" json:",omitempty"`
	DnsQuery             *DnsQuery             `xml:",omitempty" json:",omitempty"`
	FileDelete           *FileDelete           `xml:",omitempty" json:",omitempty"`
	ClipboardChange      *ClipboardChange      `xml:",omitempty" json:",omitempty"`
	ProcessTampering     *ProcessTampering     `xml:",omitempty" json:",omitempty"`
	FileDeleteDetected   *FileDeleteDetected   `xml:",omitempty" json:",omitempty"`
}
