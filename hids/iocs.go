package hids

import (
	"fmt"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/whids/api"
)

var (
	IoCRules = []engine.Rule{
		ruleHashIoC(),
		ruleDomainIoC(),
	}
)

func ruleHashIoC() (r engine.Rule) {
	r = engine.NewRule()
	r.Name = "Builtin:HashIoC"
	// FileCreate, FileDeleted and FileDeletedDetected
	r.Meta.Events = map[string][]int64{"Microsoft-Windows-Sysmon/Operational": {1, 6, 7}}
	r.Meta.Criticality = 10
	r.Matches = []string{
		fmt.Sprintf("$ioc_md5: extract('MD5=(?P<md5>[A-F0-9]{32})', Hashes) in %s", api.IoCContainerName),
		fmt.Sprintf("$ioc_sha1: extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in %s", api.IoCContainerName),
		fmt.Sprintf("$ioc_sha256: extract('SHA256=(?P<sha256>[A-F0-9]{64})', Hashes) in %s", api.IoCContainerName),
	}
	r.Condition = "$ioc_md5 or $ioc_sha1 or $ioc_sha256"
	return
}

func ruleDomainIoC() (r engine.Rule) {
	r = engine.NewRule()
	r.Name = "Builtin:DomainIoC"
	// FileCreate, FileDeleted and FileDeletedDetected
	r.Meta.Events = map[string][]int64{"Microsoft-Windows-Sysmon/Operational": {22}}
	r.Meta.Criticality = 10
	r.Matches = []string{
		fmt.Sprintf("$ioc_domain: extract('(?P<dom>\\w+\\.\\w+$)',QueryName) in %s'", api.IoCContainerName),
		fmt.Sprintf("$ioc_subdomain: extract('(?P<sub>\\w+\\.\\w+\\.\\w+$)',QueryName) in %s'", api.IoCContainerName),
		fmt.Sprintf("$ioc_hostname: extract('(?P<subsub>\\w+\\.\\w+\\.\\w+\\.\\w+$)',QueryName) in %s'", api.IoCContainerName),
	}
	r.Condition = "$ioc_domain or $ioc_subdomain or $ioc_hostname"
	return
}
