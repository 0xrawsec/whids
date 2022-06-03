package hids

import (
	"github.com/0xrawsec/gene/v2/engine"
)

const (
	eventData = "/Event/EventData/"
)

var (
	// Path definitions
	////////////////////////// Getters ///////////////////////////
	// DNS-Client logs
	pathDNSQueryValue   = engine.Path("/Event/EventData/QueryName")
	pathDNSQueryType    = engine.Path("/Event/EventData/QueryType")
	pathDNSQueryResults = engine.Path("/Event/EventData/QueryResults")

	// FileSystemAudit
	pathFSAuditProcessId  = pathSysmonProcessId
	pathFSAuditObjectName = engine.Path("/Event/EventData/ObjectName")

	// Sysmon related paths
	// Common to several events
	pathSysmonUtcTime        = engine.Path("/Event/EventData/UtcTime")
	pathSysmonImage          = engine.Path("/Event/EventData/Image")
	pathSysmonHashes         = engine.Path("/Event/EventData/Hashes")
	pathSysmonTargetFilename = engine.Path("/Event/EventData/TargetFilename")
	pathSysmonProcessGUID    = engine.Path("/Event/EventData/ProcessGuid")
	pathSysmonProcessId      = engine.Path("/Event/EventData/ProcessId")

	// EventID 1: ProcessCreate
	pathSysmonCommandLine       = engine.Path("/Event/EventData/CommandLine")
	pathSysmonParentCommandLine = engine.Path("/Event/EventData/ParentCommandLine")
	pathSysmonParentImage       = engine.Path("/Event/EventData/ParentImage")
	pathSysmonParentProcessGUID = engine.Path("/Event/EventData/ParentProcessGuid")
	pathSysmonParentProcessId   = engine.Path("/Event/EventData/ParentProcessId")
	pathSysmonUser              = engine.Path("/Event/EventData/User")
	pathSysmonIntegrityLevel    = engine.Path("/Event/EventData/IntegrityLevel")
	pathSysmonCurrentDirectory  = engine.Path("/Event/EventData/CurrentDirectory")

	// EventID 3: NetworkConnect
	pathSysmonDestIP       = engine.Path("/Event/EventData/DestinationIp")
	pathSysmonDestPort     = engine.Path("/Event/EventData/DestinationPort")
	pathSysmonDestHostname = engine.Path("/Event/EventData/DestinationHostname")

	// EventID 6/7
	pathSysmonFileVersion      = engine.Path(eventData + "FileVersion")
	pathSysmonDescription      = engine.Path(eventData + "Description")
	pathSysmonProduct          = engine.Path(eventData + "Product")
	pathSysmonCompany          = engine.Path(eventData + "Company")
	pathSysmonOriginalFileName = engine.Path(eventData + "OriginalFileName")
	pathSysmonSignature        = engine.Path("/Event/EventData/Signature")
	pathSysmonSigned           = engine.Path("/Event/EventData/Signed")
	pathSysmonSignatureStatus  = engine.Path("/Event/EventData/SignatureStatus")

	// EventID 7
	pathSysmonImageLoaded = engine.Path("/Event/EventData/ImageLoaded")

	// EventID 8: CreateRemoteThread
	pathSysmonCRTSourceProcessGuid = engine.Path("/Event/EventData/SourceProcessGuid")
	pathSysmonCRTTargetProcessGuid = engine.Path("/Event/EventData/TargetProcessGuid")

	// EventID 8/10
	pathSysmonSourceProcessId = engine.Path("/Event/EventData/SourceProcessId")
	pathSysmonTargetProcessId = engine.Path("/Event/EventData/TargetProcessId")

	// EventID 10: ProcessAccess
	pathSysmonSourceProcessGUID = engine.Path("/Event/EventData/SourceProcessGUID")
	pathSysmonTargetProcessGUID = engine.Path("/Event/EventData/TargetProcessGUID")
	pathSysmonSourceImage       = engine.Path("/Event/EventData/SourceImage")
	pathSysmonTargetImage       = engine.Path("/Event/EventData/TargetImage")

	// EventID 12,13,14: Registry
	pathSysmonEventType    = engine.Path("/Event/EventData/EventType")
	pathSysmonTargetObject = engine.Path("/Event/EventData/TargetObject")
	pathSysmonDetails      = engine.Path("/Event/EventData/Details")

	// EventID 20
	pathSysmonDestination = engine.Path("/Event/EventData/Destination")

	// EventID 22: DNSQuery
	pathQueryName    = engine.Path("/Event/EventData/QueryName")
	pathQueryResults = engine.Path("/Event/EventData/QueryResults")

	// EventID 23:
	pathSysmonArchived = engine.Path("/Event/EventData/Archived")

	// Gene criticality path
	pathGeneCriticality = engine.Path("/Event/GeneInfo/Criticality")

	///////////////////////// Setters //////////////////////////////////////
	pathProcessGeneScore    = engine.Path("/Event/EventData/ProcessThreatScore")
	pathSrcProcessGeneScore = engine.Path("/Event/EventData/SourceProcessThreatScore")
	pathTgtProcessGeneScore = engine.Path("/Event/EventData/TargetProcessThreatScore")

	pathAncestors            = engine.Path("/Event/EventData/Ancestors")
	pathParentUser           = engine.Path("/Event/EventData/ParentUser")
	pathParentIntegrityLevel = engine.Path("/Event/EventData/ParentIntegrityLevel")

	// Use to store image sizes information by hook
	pathImSize       = engine.Path("/Event/EventData/ImageSize")
	pathImLoadedSize = engine.Path("/Event/EventData/ImageLoadedSize")

	// Use to store process information by hook
	pathParentIntegrity  = engine.Path("/Event/EventData/ParentProcessIntegrity")
	pathProcessIntegrity = engine.Path("/Event/EventData/ProcessIntegrity")
	pathIntegrityTimeout = engine.Path("/Event/EventData/ProcessIntegrityTimeout")

	// Use to store pathServices information by hook
	pathServices       = engine.Path("/Event/EventData/Services")
	pathParentServices = engine.Path("/Event/EventData/ParentServices")
	pathSourceServices = engine.Path("/Event/EventData/SourceServices")
	pathTargetServices = engine.Path("/Event/EventData/TargetServices")

	// Use to store process by hook
	pathSourceIsParent = engine.Path("/Event/EventData/SourceIsParent")

	// Use to store value size by hooking on SetValue events
	pathValueSize = engine.Path("/Event/EventData/ValueSize")

	// Use to store parent image and command line in image load events
	pathImageLoadParentImage       = engine.Path("/Event/EventData/ParentImage")
	pathImageLoadParentCommandLine = engine.Path("/Event/EventData/ParentCommandLine")

	// Used to store user and integrity information in sysmon CreateRemoteThread and ProcessAccess events
	pathSourceUser              = engine.Path("/Event/EventData/SourceUser")
	pathSourceIntegrityLevel    = engine.Path("/Event/EventData/SourceIntegrityLevel")
	pathTargetUser              = engine.Path("/Event/EventData/TargetUser")
	pathTargetIntegrityLevel    = engine.Path("/Event/EventData/TargetIntegrityLevel")
	pathTargetParentProcessGuid = engine.Path("/Event/EventData/TargetParentProcessGuid")

	// Used to store Image Hashes information into any Sysmon Event
	pathImageHashes  = engine.Path("/Event/EventData/ImageHashes")
	pathSourceHashes = engine.Path("/Event/EventData/SourceHashes")
	pathTargetHashes = engine.Path("/Event/EventData/TargetHashes")

	// Used to store image signature related information
	pathImageSignature       = engine.Path("/Event/EventData/ImageSignature")
	pathImageSigned          = engine.Path("/Event/EventData/ImageSigned")
	pathImageSignatureStatus = engine.Path("/Event/EventData/ImageSignatureStatus")

	// Use to enrich Clipboard events
	pathSysmonClipboardData = engine.Path("/Event/EventData/ClipboardData")

	pathFileCount      = engine.Path("/Event/EventData/Count")
	pathFileCountByExt = engine.Path("/Event/EventData/CountByExt")
	pathFileExtension  = engine.Path("/Event/EventData/Extension")
	pathFileFrequency  = engine.Path("/Event/EventData/FrequencyEps")

	// ProcessProtectionLevel
	pathProtectionLevel       = engine.Path("/Event/EventData/ProtectionLevel")
	pathSourceProtectionLevel = engine.Path("/Event/EventData/SourceProtectionLevel")
	pathTargetProtectionLevel = engine.Path("/Event/EventData/TargetProtectionLevel")
	pathParentProtectionLevel = engine.Path("/Event/EventData/ParentProtectionLevel")
)
