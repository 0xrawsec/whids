package config

import (
	"github.com/0xrawsec/golang-utils/datastructs"
)

// Canary configuration
type Canary struct {
	HideFiles       bool     `toml:"hide-files" comment:"Flag to set to hide files"`
	HideDirectories bool     `toml:"hide-dirs" comment:"Flag to set to hide directories"`
	SetAuditACL     bool     `toml:"set-audit-acl" comment:"Set Audit ACL to the canary directories, sub-directories and files to generate File System audit events\n https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system"`
	Directories     []string `toml:"directories" comment:"Directories where canary files will be created"`
	Files           []string `toml:"files" comment:"Canary files to monitor. Files will be created if not existing"`
	Delete          bool     `toml:"delete" comment:"Whether to delete or not the canary files when service stops"`
	createdDir      *datastructs.SyncedSet
}

// Canaries structure holding canary configuration
type Canaries struct {
	Enable    bool      `toml:"enable" comment:"Enable canary files management"`
	Actions   []string  `toml:"actions" comment:"Actions to apply when a canary file is touched"`
	Whitelist []string  `toml:"whitelist" comment:"Process images being allowed to touch the canaries"`
	Canaries  []*Canary `toml:"group" comment:"Canary files to create at every run"`
}
