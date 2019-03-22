package collector

const (
	// POST based API routes

	// PostLogsURL API route used to post logs
	PostLogsURL = "/logs"
	// PostDumpURL API route used to dump things
	PostDumpURL = "/upload/dumps"

	// GET based API routes

	// GetServerKeyURL API route used to get server key
	GetServerKeyURL = "/key"
	// GetRulesURL API route used to get Gene rules available in server
	GetRulesURL = "/rules"
	// GetRulesSha256URL API route used to retrieve sha256 of latest batch of Gene rules
	GetRulesSha256URL = "/rules/sha256"
	// GetContainerListURL API route to serve the list of containers available in the Manager
	GetContainerListURL = "/containers"
	// GetContainerURL API route to get a container
	GetContainerURL = "/container/{name}"
	// GetContainerSha256URL API route to serve sha256 of the different containers
	GetContainerSha256URL = "/container/sha256/{name}"
)
