package api

// Routes used by Clients
const (
	// GET based API routes

	// EptAPIServerKeyPath API route used to get server key
	EptAPIServerKeyPath = "/key"
	// EptAPIRulesPath API route used to get Gene rules available in server
	EptAPIRulesPath = "/rules"
	// EptAPIRulesSha256Path API route used to retrieve sha256 of latest batch of Gene rules
	EptAPIRulesSha256Path = "/rules/sha256"

	// Routes to work with sysmon configuration
	EptAPISysmonConfigPath       = "/sysmon/config"
	EptAPISysmonConfigSha256Path = "/sysmon/config/sha256"

	// EptAPIIoCsPath API route used to serve IOC container
	EptAPIIoCsPath = "/iocs"
	// EptAPIIoCsSha256Path API route used to serve sha256 of IOC container
	EptAPIIoCsSha256Path = "/iocs/sha256"
	// EptAPITools API route used to update local tools
	EptAPITools = "/tools"

	// POST based API routes

	// EptAPIPostLogsPath API route used to post logs
	EptAPIPostLogsPath = "/logs"
	// EptAPIPostDumpPath API route used to dump things
	EptAPIPostDumpPath = "/upload/dumps"
	// EptAPIPostSystemInfo API route used to send system information
	EptAPIPostSystemInfo = "/info/system"

	// GET and POST routes

	// EptAPICommandPath used to GET commands and POST results
	EptAPICommandPath = "/commands"
)

var (
	eptAPIVerbosePaths = []string{
		EptAPIServerKeyPath,
		EptAPICommandPath,
		EptAPIRulesSha256Path,
		EptAPIIoCsSha256Path,
	}
)

// Routes used for Admin API
const (
	uuidRe = "[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}"

	AdmAPIUsers    = "/users"
	AdmAPIUserByID = AdmAPIUsers + "/{uuuid:" + uuidRe + "}"

	AdmAPIStatsPath     = "/stats"
	AdmAPIIocsPath      = "/iocs"
	AdmAPIRulesPath     = "/rules"
	AdmAPIEndpointsPath = "/endpoints"

	AdmAPIEndpointsOSPath = AdmAPIEndpointsPath + `/{os:\w+}`

	// Sysmon related
	AdmAPIEndpointsSysmonPath   = AdmAPIEndpointsOSPath + `/sysmon`
	AdmAPIEndpointsSysmonBinary = AdmAPIEndpointsSysmonPath + `/binary`
	AdmAPIEndpointsSysmonConfig = AdmAPIEndpointsSysmonPath + `/config`

	// OSQueryi related
	AdmAPIEndpointsOSQueryiPath   = AdmAPIEndpointsOSPath + `/osqueryi`
	AdmAPIEndpointsOSQueryiBinary = AdmAPIEndpointsOSQueryiPath + `/binary`

	AdmAPIEndpointsByIDPath = AdmAPIEndpointsPath + "/{euuid:" + uuidRe + "}"
	// Command related
	AdmAPICommandSuffix            = "/command"
	AdmAPIEndpointCommandPath      = AdmAPIEndpointsByIDPath + AdmAPICommandSuffix
	AdmAPIEndpointCommandFieldPath = AdmAPIEndpointCommandPath + "/{field}"
	// Logs related
	AdmAPILogsSuffix             = "/logs"
	AdmAPIEndpointLogsPath       = AdmAPIEndpointsByIDPath + AdmAPILogsSuffix
	AdmAPIDetectionSuffix        = "/detections"
	AdmAPIEndpointDetectionsPath = AdmAPIEndpointsByIDPath + AdmAPIDetectionSuffix
	// Reports related
	AdmAPIReportSuffix              = "/report"
	AdmAPIEndpointsReportsPath      = AdmAPIEndpointsPath + "/reports"
	AdmAPIEndpointReportPath        = AdmAPIEndpointsByIDPath + AdmAPIReportSuffix
	AdmAPIArchiveSuffix             = "/archive"
	AdmAPIEndpointReportArchivePath = AdmAPIEndpointReportPath + AdmAPIArchiveSuffix
	// Dumps related
	AdmAPIArticfactsSuffix       = "/artifacts"
	AdmAPIEndpointsArtifactsPath = AdmAPIEndpointsPath + AdmAPIArticfactsSuffix
	AdmAPIEndpointArtifacts      = AdmAPIEndpointsByIDPath + AdmAPIArticfactsSuffix
	AdmAPIEndpointArtifact       = AdmAPIEndpointArtifacts + "/{pguid:" + uuidRe + "}/{ehash:[[:xdigit:]]+}/{fname:.*}"

	//Websockets
	AdmAPIStreamEvents     = "/stream/events"
	AdmAPIStreamDetections = "/stream/detections"
)
