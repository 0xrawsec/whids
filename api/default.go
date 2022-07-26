package api

import "github.com/0xrawsec/whids/utils"

const (
	// DefaultLogPerm default logfile permission for Manager
	DefaultLogPerm = 0600
	// DefaultManagerLogSize  default size for Manager's logfiles
	DefaultManagerLogSize = utils.Mega * 100
	// DefaultKeySize default size for API key generation
	DefaultKeySize = 64
	// EptAPIDefaultPort default port used by manager's endpoint API
	EptAPIDefaultPort = 1519
	// AdmAPIDefaultPort default port used by manager's admin API
	AdmAPIDefaultPort = 1520
	// DefaultMaxUploadSize default maximum upload size
	DefaultMaxUploadSize = 100 * utils.Mega
)
