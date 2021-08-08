package api

// Routes used by Clients
const (
	// GET based API routes

	// EptAPIServerKeyPath API route used to get server key
	EptAPIServerKeyPath = "/key"
	// EptAPIRulesPath API route used to get Gene rules available in server
	EptAPIRulesPath = "/rules"
	// EptAPIRulesSha256Path API route used to retrieve sha256 of latest batch of Gene rules
	EptAPIRulesSha256Path = "/rules/sha256"
	// EptAPIContainerListPath API route to serve the list of containers available in the Manager
	EptAPIContainerListPath = "/containers"
	// EptAPIContainerPath API route to get a container
	EptAPIContainerPath = "/container/{name}"
	// EptAPIContainerSha256Path API route to serve sha256 of the different containers
	EptAPIContainerSha256Path = "/container/sha256/{name}"

	// POST based API routes

	// EptAPIPostLogsPath API route used to post logs
	EptAPIPostLogsPath = "/logs"
	// EptAPIPostDumpPath API route used to dump things
	EptAPIPostDumpPath = "/upload/dumps"

	// GET and POST routes

	// EptAPICommandPath used to GET commands and POST results
	EptAPICommandPath = "/commands"
)

var (
	eptAPIVerbosePaths = []string{
		EptAPIServerKeyPath,
		EptAPICommandPath,
		EptAPIRulesSha256Path,
		EptAPIContainerListPath,
	}
)

// Routes used for Admin API
const (
	uuidRe                  = "[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}"
	AdmAPIStatsPath         = "/stats"
	AdmAPIRulesPath         = "/rules"
	AdmAPIRulesReloadPath   = "/rules/reload"
	AdmAPIRulesSavePath     = "/rules/save"
	AdmAPIEndpointsPath     = "/endpoints"
	AdmAPIEndpointsByIDPath = AdmAPIEndpointsPath + "/{euuid:" + uuidRe + "}"
	// Command related
	AdmAPIEndpointCommandPath      = AdmAPIEndpointsByIDPath + "/command"
	AdmAPIEndpointCommandFieldPath = AdmAPIEndpointCommandPath + "/{field}"
	// Logs related
	AdmAPIEndpointLogsPath       = AdmAPIEndpointsByIDPath + "/logs"
	AdmAPIDetectionPart          = "/detections"
	AdmAPIEndpointDetectionsPath = AdmAPIEndpointsByIDPath + AdmAPIDetectionPart
	// Reports related
	AdmAPIEndpointsReportsPath = AdmAPIEndpointsPath + "/reports"
	AdmAPIEndpointReportPath   = AdmAPIEndpointsByIDPath + "/report"
	// Dumps related
	admAPIArtifactsPart          = "/artifacts"
	AdmAPIEndpointsArtifactsPath = AdmAPIEndpointsPath + admAPIArtifactsPart
	AdmAPIEndpointArtifacts      = AdmAPIEndpointsByIDPath + admAPIArtifactsPart
	AdmAPIEndpointArtifact       = AdmAPIEndpointArtifacts + "/{pguid:" + uuidRe + "}/{ehash:[[:xdigit:]]+}/{fname:.*}"

	//Websockets
	AdmAPIStreamEvents     = "/stream/events"
	AdmAPIStreamDetections = "/stream/detections"
)
