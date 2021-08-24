package hids

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/utils"
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

// expands environment variables found in directories
func (c *Canary) expandDir() (dirs []string) {
	return utils.ExpandEnvs(c.Directories...)
}

// create the canary files and directories
func (c *Canary) create() (err error) {
	c.createdDir = datastructs.NewSyncedSet()

	for _, dir := range c.expandDir() {
		if !fsutil.Exists(dir) {
			if err := os.MkdirAll(dir, 0777); err != nil {
				return err
			}
			if c.HideDirectories {
				if err := utils.HideFile(dir); err != nil {
					return err
				}
			}
			c.createdDir.Add(dir)
		}
	}

	for _, fp := range c.paths() {
		if !fsutil.Exists(fp) {
			var fd *os.File

			if fd, err = os.Create(fp); err != nil {
				return err
			}
			defer fd.Close()
			rand.Seed(time.Now().Unix())
			buf := [1024]byte{}
			size := rand.Int() % 50 * utils.Mega
			written, n := 0, 0
			for written < size && err == nil {
				if _, err = rand.Read(buf[:]); err != nil {
					continue
				}
				n, err = fd.Write(buf[:])
				written += n
			}
			fd.Close()

			if c.HideFiles {
				if err := utils.HideFile(fp); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// clean the canary files
func (c *Canary) clean() {
	if c.Delete {
		// we remove canary files
		for _, fp := range c.paths() {
			os.Remove(fp)
		}

		// we remove only empty directories
		for _, dir := range c.expandDir() {
			os.Remove(dir)
		}

		// we remove directory which have been created
		for _, i := range c.createdDir.List() {
			dir := i.(string)
			os.RemoveAll(dir)
		}
	}
}

// return a list containing the full paths of the canary files
func (c *Canary) paths() (files []string) {
	files = make([]string, 0, len(c.Files)*len(c.Directories))
	for _, dir := range c.expandDir() {
		for _, fn := range c.Files {
			files = append(files, filepath.Join(dir, fn))
		}
	}
	return
}

// CanariesConfig structure holding canary configuration
type CanariesConfig struct {
	Enable    bool      `toml:"enable" comment:"Enable canary files management"`
	Actions   []string  `toml:"actions" comment:"Actions to apply when a canary file is touched"`
	Whitelist []string  `toml:"whitelist" comment:"Process images being allowed to touch the canaries"`
	Canaries  []*Canary `toml:"group" comment:"Canary files to create at every run"`
}

func (c *CanariesConfig) canaryRegexp() string {
	repaths := make([]string, 0)
	for _, c := range c.Canaries {

		// adding list of created dir
		for _, i := range c.createdDir.List() {
			dir := fmt.Sprintf("%s%c", i.(string), os.PathSeparator)
			repaths = append(repaths, regexp.QuoteMeta(dir))
		}

		for _, fp := range c.paths() {
			dir := filepath.Dir(fp)
			if !c.createdDir.Contains(dir) {
				repaths = append(repaths, regexp.QuoteMeta(fp))
			}
		}
	}
	return fmt.Sprintf("(?i:(%s))", strings.Join(repaths, "|"))
}

func (c *CanariesConfig) whitelistRegexp() string {
	wl := make([]string, 0, len(c.Whitelist))
	for _, im := range c.Whitelist {
		wl = append(wl, regexp.QuoteMeta(im))
	}
	return fmt.Sprintf("(?i:(%s))", strings.Join(wl, "|"))
}

// Configure creates canaries and set ACLs if needed
func (c *CanariesConfig) Configure() {
	auditDirs := make([]string, 0)
	if c.Enable {
		for _, cf := range c.Canaries {
			// add the list of directories to audit
			if cf.SetAuditACL {
				auditDirs = append(auditDirs, cf.expandDir()...)
			}

			if err := cf.create(); err != nil {
				log.Errorf("Failed at creating canary: %s", err)
			}
		}

		// run this function async as it might take a little bit of time
		go func() {
			if err := utils.SetEDRAuditACL(auditDirs...); err != nil {
				log.Errorf("Error while setting canaries' Audit ACLs: %s", err)
			}
		}()
	}
}

// RestoreACLs restore EDR configured ACLs
func (c *CanariesConfig) RestoreACLs() {
	auditDirs := make([]string, 0)
	for _, cf := range c.Canaries {
		// add the list of directories to audit
		if cf.SetAuditACL {
			auditDirs = append(auditDirs, cf.expandDir()...)
		}
	}
	if err := utils.RemoveEDRAuditACL(auditDirs...); err != nil {
		log.Errorf("Error while setting canaries' Audit ACLs: %s", err)
	}
}

// GenRuleFSAudit generate a rule matching FS Audit events for the configured canaries
func (c *CanariesConfig) GenRuleFSAudit() (r engine.Rule) {
	r = engine.NewRule()
	r.Name = "Builtin:CanaryAccessed"
	r.Meta.Events = map[string][]int64{"Security": {4663}}
	r.Meta.Criticality = 10
	r.Matches = []string{
		"$read: AccessMask &= '0x1'",
		"$write: AccessMask &= '0x2'",
		"$append: AccessMask &= '0x4'",
		fmt.Sprintf("$wl_images: ProcessName ~= '%s'", c.whitelistRegexp()),
		fmt.Sprintf("$canary: ObjectName ~= '%s'", c.canaryRegexp()),
	}
	r.Condition = "!$wl_images and ($read or $write or $append) and $canary"
	r.Actions = append(r.Actions, c.Actions...)
	return
}

// GenRuleSysmon generate a rule matching sysmon events for the configured canaries
func (c *CanariesConfig) GenRuleSysmon() (r engine.Rule) {
	r = engine.NewRule()
	r.Name = "Builtin:CanaryModified"
	// FileCreate, FileDeleted and FileDeletedDetected
	r.Meta.Events = map[string][]int64{"Microsoft-Windows-Sysmon/Operational": {11, 23, 26}}
	r.Meta.Criticality = 10
	r.Matches = []string{
		fmt.Sprintf("$wl_images: Image ~= '%s'", c.whitelistRegexp()),
		fmt.Sprintf("$canary: TargetFilename ~= '%s'", c.canaryRegexp()),
	}
	r.Condition = "!$wl_images and $canary"
	r.Actions = append(r.Actions, c.Actions...)
	return
}

// Clean cleans up the canaries
func (c *CanariesConfig) Clean() {
	if c.Enable {
		for _, cf := range c.Canaries {
			cf.clean()
		}
	}
}
