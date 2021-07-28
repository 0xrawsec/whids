package hids

import "github.com/0xrawsec/golang-evtx/evtx"

var (
	// Path definitions
	////////////////////////// Getters ///////////////////////////
	// DNS-Client logs
	pathDNSQueryValue   = evtx.Path("/Event/EventData/QueryName")
	pathDNSQueryType    = evtx.Path("/Event/EventData/QueryType")
	pathDNSQueryResults = evtx.Path("/Event/EventData/QueryResults")

	// FileSystemAudit
	pathFSAuditProcessId  = pathSysmonProcessId
	pathFSAuditObjectName = evtx.Path("/Event/EventData/ObjectName")

	// Sysmon related paths
	// Common to several events
	pathSysmonUtcTime        = evtx.Path("/Event/EventData/UtcTime")
	pathSysmonImage          = evtx.Path("/Event/EventData/Image")
	pathSysmonHashes         = evtx.Path("/Event/EventData/Hashes")
	pathSysmonTargetFilename = evtx.Path("/Event/EventData/TargetFilename")
	pathSysmonProcessGUID    = evtx.Path("/Event/EventData/ProcessGuid")
	pathSysmonProcessId      = evtx.Path("/Event/EventData/ProcessId")

	// EventID 1: ProcessCreate
	pathSysmonCommandLine       = evtx.Path("/Event/EventData/CommandLine")
	pathSysmonParentCommandLine = evtx.Path("/Event/EventData/ParentCommandLine")
	pathSysmonParentImage       = evtx.Path("/Event/EventData/ParentImage")
	pathSysmonParentProcessGUID = evtx.Path("/Event/EventData/ParentProcessGuid")
	pathSysmonParentProcessId   = evtx.Path("/Event/EventData/ParentProcessId")
	pathSysmonUser              = evtx.Path("/Event/EventData/User")
	pathSysmonIntegrityLevel    = evtx.Path("/Event/EventData/IntegrityLevel")
	pathSysmonCurrentDirectory  = evtx.Path("/Event/EventData/CurrentDirectory")

	// EventID 3: NetworkConnect
	pathSysmonDestIP       = evtx.Path("/Event/EventData/DestinationIp")
	pathSysmonDestPort     = evtx.Path("/Event/EventData/DestinationPort")
	pathSysmonDestHostname = evtx.Path("/Event/EventData/DestinationHostname")

	// EventID 6/7
	pathSysmonSignature       = evtx.Path("/Event/EventData/Signature")
	pathSysmonSigned          = evtx.Path("/Event/EventData/Signed")
	pathSysmonSignatureStatus = evtx.Path("/Event/EventData/SignatureStatus")

	// EventID 7
	pathSysmonImageLoaded = evtx.Path("/Event/EventData/ImageLoaded")

	// EventID 8: CreateRemoteThread
	pathSysmonCRTSourceProcessGuid = evtx.Path("/Event/EventData/SourceProcessGuid")
	pathSysmonCRTTargetProcessGuid = evtx.Path("/Event/EventData/TargetProcessGuid")

	// EventID 8/10
	pathSysmonSourceProcessId = evtx.Path("/Event/EventData/SourceProcessId")
	pathSysmonTargetProcessId = evtx.Path("/Event/EventData/TargetProcessId")

	// EventID 10: ProcessAccess
	pathSysmonSourceProcessGUID = evtx.Path("/Event/EventData/SourceProcessGUID")
	pathSysmonTargetProcessGUID = evtx.Path("/Event/EventData/TargetProcessGUID")
	pathSysmonSourceImage       = evtx.Path("/Event/EventData/SourceImage")
	pathSysmonTargetImage       = evtx.Path("/Event/EventData/TargetImage")

	// EventID 12,13,14: Registry
	pathSysmonTargetObject = evtx.Path("/Event/EventData/TargetObject")
	pathSysmonDetails      = evtx.Path("/Event/EventData/Details")

	// EventID 20
	pathSysmonDestination = evtx.Path("/Event/EventData/Destination")

	// EventID 22: DNSQuery
	pathQueryName    = evtx.Path("/Event/EventData/QueryName")
	pathQueryResults = evtx.Path("/Event/EventData/QueryResults")

	// EventID 23:
	pathSysmonArchived = evtx.Path("/Event/EventData/Archived")

	// Gene criticality path
	pathGeneCriticality = evtx.Path("/Event/GeneInfo/Criticality")

	///////////////////////// Setters //////////////////////////////////////
	pathProcessGeneScore    = evtx.Path("/Event/EventData/ProcessThreatScore")
	pathSrcProcessGeneScore = evtx.Path("/Event/EventData/SourceProcessThreatScore")
	pathTgtProcessGeneScore = evtx.Path("/Event/EventData/TargetProcessThreatScore")

	pathAncestors            = evtx.Path("/Event/EventData/Ancestors")
	pathParentUser           = evtx.Path("/Event/EventData/ParentUser")
	pathParentIntegrityLevel = evtx.Path("/Event/EventData/ParentIntegrityLevel")

	// Use to store image sizes information by hook
	pathImSize       = evtx.Path("/Event/EventData/ImageSize")
	pathImLoadedSize = evtx.Path("/Event/EventData/ImageLoadedSize")

	// Use to store process information by hook
	pathParentIntegrity  = evtx.Path("/Event/EventData/ParentProcessIntegrity")
	pathProcessIntegrity = evtx.Path("/Event/EventData/ProcessIntegrity")
	pathIntegrityTimeout = evtx.Path("/Event/EventData/ProcessIntegrityTimeout")

	// Use to store pathServices information by hook
	pathServices       = evtx.Path("/Event/EventData/Services")
	pathParentServices = evtx.Path("/Event/EventData/ParentServices")
	pathSourceServices = evtx.Path("/Event/EventData/SourceServices")
	pathTargetServices = evtx.Path("/Event/EventData/TargetServices")

	// Use to store process by hook
	pathSourceIsParent = evtx.Path("/Event/EventData/SourceIsParent")

	// Use to store value size by hooking on SetValue events
	pathValueSize = evtx.Path("/Event/EventData/ValueSize")

	// Use to store parent image and command line in image load events
	pathImageLoadParentImage       = evtx.Path("/Event/EventData/ParentImage")
	pathImageLoadParentCommandLine = evtx.Path("/Event/EventData/ParentCommandLine")

	// Used to store user and integrity information in sysmon CreateRemoteThread and ProcessAccess events
	pathSourceUser              = evtx.Path("/Event/EventData/SourceUser")
	pathSourceIntegrityLevel    = evtx.Path("/Event/EventData/SourceIntegrityLevel")
	pathTargetUser              = evtx.Path("/Event/EventData/TargetUser")
	pathTargetIntegrityLevel    = evtx.Path("/Event/EventData/TargetIntegrityLevel")
	pathTargetParentProcessGuid = evtx.Path("/Event/EventData/TargetParentProcessGuid")

	// Used to store Image Hashes information into any Sysmon Event
	pathImageHashes  = evtx.Path("/Event/EventData/ImageHashes")
	pathSourceHashes = evtx.Path("/Event/EventData/SourceHashes")
	pathTargetHashes = evtx.Path("/Event/EventData/TargetHashes")

	// Used to store image signature related information
	pathImageSignature       = evtx.Path("/Event/EventData/ImageSignature")
	pathImageSigned          = evtx.Path("/Event/EventData/ImageSigned")
	pathImageSignatureStatus = evtx.Path("/Event/EventData/ImageSignatureStatus")

	// Use to enrich Clipboard events
	pathSysmonClipboardData = evtx.Path("/Event/EventData/ClipboardData")

	pathFileCount      = evtx.Path("/Event/EventData/Count")
	pathFileCountByExt = evtx.Path("/Event/EventData/CountByExt")
	pathFileExtension  = evtx.Path("/Event/EventData/Extension")
	pathFileFrequency  = evtx.Path("/Event/EventData/FrequencyEps")
)
