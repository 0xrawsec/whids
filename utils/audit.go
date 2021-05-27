package utils

import (
	"fmt"
	"os/exec"

	"github.com/0xrawsec/whids/utils/powershell"
)

const (
	auditPolEnable  = `auditpol /set /subcategory:"%s" /failure:enable /success:enable`
	auditPolDisable = `auditpol /set /subcategory:"%s" /failure:disable /success:disable`
)

var (
	auditPolMap = map[string]string{
		"Security System Extension":              "{0CCE9211-69AE-11D9-BED3-505054503030}",
		"System Integrity":                       "{0CCE9212-69AE-11D9-BED3-505054503030}",
		"IPsec Driver":                           "{0CCE9213-69AE-11D9-BED3-505054503030}",
		"Other System Events":                    "{0CCE9214-69AE-11D9-BED3-505054503030}",
		"Security State Change":                  "{0CCE9210-69AE-11D9-BED3-505054503030}",
		"Logon":                                  "{0CCE9215-69AE-11D9-BED3-505054503030}",
		"Logoff":                                 "{0CCE9216-69AE-11D9-BED3-505054503030}",
		"Account Lockout":                        "{0CCE9217-69AE-11D9-BED3-505054503030}",
		"IPsec Main Mode":                        "{0CCE9218-69AE-11D9-BED3-505054503030}",
		"IPsec Quick Mode":                       "{0CCE9219-69AE-11D9-BED3-505054503030}",
		"IPsec Extended Mode":                    "{0CCE921A-69AE-11D9-BED3-505054503030}",
		"Special Logon":                          "{0CCE921B-69AE-11D9-BED3-505054503030}",
		"Other Logon/Logoff Events":              "{0CCE921C-69AE-11D9-BED3-505054503030}",
		"Network Policy Server":                  "{0CCE9243-69AE-11D9-BED3-505054503030}",
		"User / Device Claims":                   "{0CCE9247-69AE-11D9-BED3-505054503030}",
		"Group Membership":                       "{0CCE9249-69AE-11D9-BED3-505054503030}",
		"File System":                            "{0CCE921D-69AE-11D9-BED3-505054503030}",
		"Registry":                               "{0CCE921E-69AE-11D9-BED3-505054503030}",
		"Kernel Object":                          "{0CCE921F-69AE-11D9-BED3-505054503030}",
		"SAM":                                    "{0CCE9220-69AE-11D9-BED3-505054503030}",
		"Certification Services":                 "{0CCE9221-69AE-11D9-BED3-505054503030}",
		"Application Generated":                  "{0CCE9222-69AE-11D9-BED3-505054503030}",
		"Handle Manipulation":                    "{0CCE9223-69AE-11D9-BED3-505054503030}",
		"File Share":                             "{0CCE9224-69AE-11D9-BED3-505054503030}",
		"Filtering Platform Packet Drop":         "{0CCE9225-69AE-11D9-BED3-505054503030}",
		"Filtering Platform Connection":          "{0CCE9226-69AE-11D9-BED3-505054503030}",
		"Other Object Access Events":             "{0CCE9227-69AE-11D9-BED3-505054503030}",
		"Detailed File Share":                    "{0CCE9244-69AE-11D9-BED3-505054503030}",
		"Removable Storage":                      "{0CCE9245-69AE-11D9-BED3-505054503030}",
		"Central Policy Staging":                 "{0CCE9246-69AE-11D9-BED3-505054503030}",
		"Non Sensitive Privilege Use":            "{0CCE9229-69AE-11D9-BED3-505054503030}",
		"Other Privilege Use Events":             "{0CCE922A-69AE-11D9-BED3-505054503030}",
		"Sensitive Privilege Use":                "{0CCE9228-69AE-11D9-BED3-505054503030}",
		"Process Creation":                       "{0CCE922B-69AE-11D9-BED3-505054503030}",
		"Process Termination":                    "{0CCE922C-69AE-11D9-BED3-505054503030}",
		"DPAPI Activity":                         "{0CCE922D-69AE-11D9-BED3-505054503030}",
		"RPC Events":                             "{0CCE922E-69AE-11D9-BED3-505054503030}",
		"Plug and Play Events":                   "{0CCE9248-69AE-11D9-BED3-505054503030}",
		"Token Right Adjusted Events":            "{0CCE924A-69AE-11D9-BED3-505054503030}",
		"Audit Policy Change":                    "{0CCE922F-69AE-11D9-BED3-505054503030}",
		"Authentication Policy Change":           "{0CCE9230-69AE-11D9-BED3-505054503030}",
		"Authorization Policy Change":            "{0CCE9231-69AE-11D9-BED3-505054503030}",
		"MPSSVC Rule-Level Policy Change":        "{0CCE9232-69AE-11D9-BED3-505054503030}",
		"Filtering Platform Policy Change":       "{0CCE9233-69AE-11D9-BED3-505054503030}",
		"Other Policy Change Events":             "{0CCE9234-69AE-11D9-BED3-505054503030}",
		"Computer Account Management":            "{0CCE9236-69AE-11D9-BED3-505054503030}",
		"Security Group Management":              "{0CCE9237-69AE-11D9-BED3-505054503030}",
		"Distribution Group Management":          "{0CCE9238-69AE-11D9-BED3-505054503030}",
		"Application Group Management":           "{0CCE9239-69AE-11D9-BED3-505054503030}",
		"Other Account Management Events":        "{0CCE923A-69AE-11D9-BED3-505054503030}",
		"User Account Management":                "{0CCE9235-69AE-11D9-BED3-505054503030}",
		"Directory Service Access":               "{0CCE923B-69AE-11D9-BED3-505054503030}",
		"Directory Service Changes":              "{0CCE923C-69AE-11D9-BED3-505054503030}",
		"Directory Service Replication":          "{0CCE923D-69AE-11D9-BED3-505054503030}",
		"Detailed Directory Service Replication": "{0CCE923E-69AE-11D9-BED3-505054503030}",
		"Kerberos Service Ticket Operations":     "{0CCE9240-69AE-11D9-BED3-505054503030}",
		"Other Account Logon Events":             "{0CCE9241-69AE-11D9-BED3-505054503030}",
		"Kerberos Authentication Service":        "{0CCE9242-69AE-11D9-BED3-505054503030}",
		"Credential Validation":                  "{0CCE923F-69AE-11D9-BED3-505054503030}",
	}
)

func resolveSubcategory(subCatOrGuid string) string {
	if guid, ok := auditPolMap[subCatOrGuid]; ok {
		return guid
	}
	for _, guid := range auditPolMap {
		if subCatOrGuid == guid {
			return guid
		}
	}
	return ""
}

func SetAuditPolicy(subCatOrGuid string, success, failure bool) error {
	var guid string

	aSuccess := "/success:disable"
	aFailure := "/failure:disable"

	if guid = resolveSubcategory(subCatOrGuid); guid == "" {
		return fmt.Errorf("Unknown Audit Policy subcategory: %s", subCatOrGuid)
	}

	if success {
		aSuccess = "/success:enable"
	}

	if failure {
		aFailure = "/failure:enable"
	}

	args := []string{
		"/set",
		fmt.Sprintf("/subcategory:%s", guid),
		aFailure,
		aSuccess,
	}

	return exec.Command("auditpol", args...).Run()
}

func EnableAuditPolicy(subCatOrGuid string) error {
	return SetAuditPolicy(subCatOrGuid, true, true)
}

func DisableAuditPolicy(subCatOrGuid string) error {
	return SetAuditPolicy(subCatOrGuid, false, false)
}

const (
	// source of inspiration: https://technochat.in/set-file-system-auditing-via-powershell/
	funcAuditACL = `Function SetAudit-ACL {
	[cmdletbinding()]
	Param (
	[string]$TargetFolder,
	[string]$AuditUser,
	[string]$AuditRules,
	[string]$InheritType,
	[string]$AuditType
	)
	$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"None",$AuditType)
	$ACL = Get-Acl -Audit $TargetFolder
	foreach ( $a in $ACL.Audit )
	{ 
		if ( $a.FileSystemRights -eq $AccessRule.FileSystemRights -And $a.AuditFlags -eq $AccessRule.AuditFlags -And $a.IdentityReference -eq $AccessRule.IdentityReference)
		{
			return
		}
	}
	$ACL.AddAuditRule($AccessRule)
	$ACL | Set-Acl $TargetFolder
	}

	Function RemoveAudit-Acl {
	[cmdletbinding()]
	Param (
	[string]$TargetFolder,
	[string]$AuditUser,
	[string]$AuditRules,
	[string]$InheritType,
	[string]$AuditType
	)
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"None",$AuditType)
		$ACL = Get-Acl -Audit $TargetFolder
		$ACL.RemoveAuditRuleSpecific($AccessRule)
		$ACL | Set-Acl $TargetFolder
	}
	`

	setAuditACLFmt    = `SetAudit-ACL -TargetFolder "%s" -AuditUser "Everyone" -AuditRules "Delete,DeleteSubdirectoriesAndFiles,Modify,ChangePermissions,Takeownership" -InheritType "ContainerInherit,ObjectInherit" -AuditType "Success, Failure"`
	removeAuditACLFmt = `RemoveAudit-ACL -TargetFolder "%s" -AuditUser "Everyone" -AuditRules "Delete,DeleteSubdirectoriesAndFiles,Modify,ChangePermissions,Takeownership" -InheritType "ContainerInherit,ObjectInherit" -AuditType "Success, Failure"`
)

func SetEDRAuditACL(directories ...string) (err error) {
	var p *powershell.Powershell

	if len(directories) == 0 {
		return nil
	}

	if p, err = powershell.NewShell(); err != nil {
		return fmt.Errorf("Failed at spawning a new shell: %w", err)
	}

	p.ImportFunction(funcAuditACL)
	for _, d := range directories {
		p.ExecuteString(fmt.Sprintf(setAuditACLFmt, StdDir(d)))
	}

	return p.Exit()
}

func RemoveEDRAuditACL(directories ...string) (err error) {
	var p *powershell.Powershell

	if len(directories) == 0 {
		return nil
	}

	if p, err = powershell.NewShell(); err != nil {
		return fmt.Errorf("Failed at spawning a new shell: %w", err)
	}

	p.ImportFunction(funcAuditACL)
	for _, d := range directories {
		p.ExecuteString(fmt.Sprintf(removeAuditACLFmt, StdDir(d)))
	}

	return p.Exit()
}
