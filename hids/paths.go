package hids

import (
	"github.com/0xrawsec/gene/v2/engine"
)

const (
	eventData = "/Event/EventData/"
)

func EventDataPath(field string) *engine.XPath {
	return engine.Path(eventData + field)
}

var (
	// Path definitions
	////////////////////////// Getters ///////////////////////////
	// DNS-Client logs
	pathDNSQueryValue   = EventDataPath("QueryName")
	pathDNSQueryType    = EventDataPath("QueryType")
	pathDNSQueryResults = EventDataPath("QueryResults")

	// FileSystemAudit
	pathFSAuditProcessId  = pathSysmonProcessId
	pathFSAuditObjectName = EventDataPath("ObjectName")

	// Sysmon related paths
	// Common to several events
	pathSysmonUtcTime        = EventDataPath("UtcTime")
	pathSysmonImage          = EventDataPath("Image")
	pathSysmonHashes         = EventDataPath("Hashes")
	pathSysmonTargetFilename = EventDataPath("TargetFilename")
	pathSysmonProcessGUID    = EventDataPath("ProcessGuid")
	pathSysmonProcessId      = EventDataPath("ProcessId")

	// EventID 1: ProcessCreate
	pathSysmonCommandLine       = EventDataPath("CommandLine")
	pathSysmonParentCommandLine = EventDataPath("ParentCommandLine")
	pathSysmonParentImage       = EventDataPath("ParentImage")
	pathSysmonParentProcessGUID = EventDataPath("ParentProcessGuid")
	pathSysmonParentProcessId   = EventDataPath("ParentProcessId")
	pathSysmonUser              = EventDataPath("User")
	pathSysmonIntegrityLevel    = EventDataPath("IntegrityLevel")
	pathSysmonCurrentDirectory  = EventDataPath("CurrentDirectory")

	// EventID 3: NetworkConnect
	pathSysmonDestIP       = EventDataPath("DestinationIp")
	pathSysmonDestPort     = EventDataPath("DestinationPort")
	pathSysmonDestHostname = EventDataPath("DestinationHostname")

	// EventID 6/7
	pathSysmonFileVersion      = engine.Path(eventData + "FileVersion")
	pathSysmonDescription      = engine.Path(eventData + "Description")
	pathSysmonProduct          = engine.Path(eventData + "Product")
	pathSysmonCompany          = engine.Path(eventData + "Company")
	pathSysmonOriginalFileName = engine.Path(eventData + "OriginalFileName")
	pathSysmonSignature        = EventDataPath("Signature")
	pathSysmonSigned           = EventDataPath("Signed")
	pathSysmonSignatureStatus  = EventDataPath("SignatureStatus")

	// EventID 7
	pathSysmonImageLoaded = EventDataPath("ImageLoaded")

	// EventID 8: CreateRemoteThread
	pathSysmonCRTSourceProcessGuid = EventDataPath("SourceProcessGuid")
	pathSysmonCRTTargetProcessGuid = EventDataPath("TargetProcessGuid")

	// EventID 8/10
	pathSysmonSourceProcessId = EventDataPath("SourceProcessId")
	pathSysmonTargetProcessId = EventDataPath("TargetProcessId")

	// EventID 10: ProcessAccess
	pathSysmonSourceProcessGUID = EventDataPath("SourceProcessGUID")
	pathSysmonTargetProcessGUID = EventDataPath("TargetProcessGUID")
	pathSysmonSourceImage       = EventDataPath("SourceImage")
	pathSysmonTargetImage       = EventDataPath("TargetImage")

	// EventID 12,13,14: Registry
	pathSysmonEventType    = EventDataPath("EventType")
	pathSysmonTargetObject = EventDataPath("TargetObject")
	pathSysmonDetails      = EventDataPath("Details")

	// EventID 20
	pathSysmonDestination = EventDataPath("Destination")

	// EventID 22: DNSQuery
	pathQueryName    = EventDataPath("QueryName")
	pathQueryResults = EventDataPath("QueryResults")

	// EventID 23:
	pathSysmonArchived = EventDataPath("Archived")

	// Gene criticality path
	pathGeneCriticality = engine.Path("/Event/GeneInfo/Criticality")

	///////////////////////// Setters //////////////////////////////////////
	pathProcessGeneScore    = EventDataPath("ProcessThreatScore")
	pathSrcProcessGeneScore = EventDataPath("SourceProcessThreatScore")
	pathTgtProcessGeneScore = EventDataPath("TargetProcessThreatScore")

	pathAncestors            = EventDataPath("Ancestors")
	pathParentUser           = EventDataPath("ParentUser")
	pathParentIntegrityLevel = EventDataPath("ParentIntegrityLevel")

	// Use to store image sizes information by hook
	pathImSize       = EventDataPath("ImageSize")
	pathImLoadedSize = EventDataPath("ImageLoadedSize")

	// Use to store process information by hook
	pathParentIntegrity  = EventDataPath("ParentProcessIntegrity")
	pathProcessIntegrity = EventDataPath("ProcessIntegrity")
	pathIntegrityTimeout = EventDataPath("ProcessIntegrityTimeout")

	// Use to store pathServices information by hook
	pathServices       = EventDataPath("Services")
	pathParentServices = EventDataPath("ParentServices")
	pathSourceServices = EventDataPath("SourceServices")
	pathTargetServices = EventDataPath("TargetServices")

	// Use to store process by hook
	pathSourceIsParent = EventDataPath("SourceIsParent")

	// Use to store value size by hooking on SetValue events
	pathValueSize = EventDataPath("ValueSize")

	// Use to store parent image and command line in image load events
	pathImageLoadParentImage       = EventDataPath("ParentImage")
	pathImageLoadParentCommandLine = EventDataPath("ParentCommandLine")

	// Used to store user and integrity information in sysmon CreateRemoteThread and ProcessAccess events
	pathSourceUser              = EventDataPath("SourceUser")
	pathSourceIntegrityLevel    = EventDataPath("SourceIntegrityLevel")
	pathTargetUser              = EventDataPath("TargetUser")
	pathTargetIntegrityLevel    = EventDataPath("TargetIntegrityLevel")
	pathTargetParentProcessGuid = EventDataPath("TargetParentProcessGuid")

	// Used to store Image Hashes information into any Sysmon Event
	pathImageHashes  = EventDataPath("ImageHashes")
	pathSourceHashes = EventDataPath("SourceHashes")
	pathTargetHashes = EventDataPath("TargetHashes")

	// Used to store image signature related information
	pathImageSignature       = EventDataPath("ImageSignature")
	pathImageSigned          = EventDataPath("ImageSigned")
	pathImageSignatureStatus = EventDataPath("ImageSignatureStatus")

	// Use to enrich Clipboard events
	pathSysmonClipboardData = EventDataPath("ClipboardData")

	pathFileCount      = EventDataPath("Count")
	pathFileCountByExt = EventDataPath("CountByExt")
	pathFileExtension  = EventDataPath("Extension")
	pathFileFrequency  = EventDataPath("FrequencyEps")

	// ProcessProtectionLevel
	pathProtectionLevel       = EventDataPath("ProtectionLevel")
	pathSourceProtectionLevel = EventDataPath("SourceProtectionLevel")
	pathTargetProtectionLevel = EventDataPath("TargetProtectionLevel")
	pathParentProtectionLevel = EventDataPath("ParentProtectionLevel")
)
