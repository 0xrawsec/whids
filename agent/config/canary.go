package config

import (
	"github.com/0xrawsec/golang-utils/datastructs"
)

// Canary configuration
type Canary struct {
	HideFiles       bool     `json:"hide-files" toml:"hide-files" comment:"Flag to set to hide files"`
	HideDirectories bool     `json:"hide-dirs" toml:"hide-dirs" comment:"Flag to set to hide directories"`
	SetAuditACL     bool     `json:"set-audit-acl" toml:"set-audit-acl" comment:"Set Audit ACL to the canary directories, sub-directories and files to generate File System audit events\n https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system"`
	Directories     []string `json:"directories" toml:"directories" comment:"Directories where canary files will be created"`
	Files           []string `json:"files" toml:"files" comment:"Canary files to monitor. Files will be created if not existing"`
	Delete          bool     `json:"delete" toml:"delete" comment:"Whether to delete or not the canary files when service stops"`
	createdDir      *datastructs.SyncedSet
}

// Canaries structure holding canary configuration
type Canaries struct {
	Enable    bool      `json:"enable" toml:"enable" comment:"Enable canary files management"`
	Actions   []string  `json:"actions" toml:"actions" comment:"Actions to apply when a canary file is touched"`
	Whitelist []string  `json:"whitelist" toml:"whitelist" comment:"Process images being allowed to touch the canaries"`
	Canaries  []*Canary `json:"group" toml:"group" comment:"Canary files to create at every run"`
}
