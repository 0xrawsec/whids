package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xrawsec/gene/rules"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/utils"
)

type Canary struct {
	HideFiles       bool     `toml:"hide-files" comment:"Flag to set to hide files"`
	HideDirectories bool     `toml:"hide-dirs" comment:"Flag to set to hide directories"`
	SetAuditACL     bool     `toml:"set-audit-acl" comment:"Set Audit ACL to the canary directories, sub-directories and files to generate File System audit events\n https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system"`
	Directories     []string `toml:"directories" comment:"Directory where canary files will be located"`
	Files           []string `toml:"files" comment:"Canary files to monitor. Files will be created if not existing"`
	Delete          bool     `toml:"delete" comment:"Whether to delete or not the canary files when service stops"`
	createdDir      datastructs.SyncedSet
}

func (c *Canary) ExpandedDir() (dirs []string) {
	return utils.ExpandEnvs(c.Directories...)
}

func (c *Canary) Create() (err error) {
	c.createdDir = datastructs.NewSyncedSet()

	for _, dir := range c.ExpandedDir() {
		if !fsutil.Exists(dir) {
			if err := os.MkdirAll(dir, 777); err != nil {
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

	for _, fp := range c.Paths() {
		if !fsutil.Exists(fp) {
			var fd *os.File

			if fd, err = os.Create(fp); err != nil {
				return err
			}
			defer fd.Close()
			rand.Seed(time.Now().Unix())
			buf := [1024]byte{}
			size := rand.Int() % 50 * Mega
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

func (c *Canary) Clean() {
	if c.Delete {
		// we remove canary files
		for _, fp := range c.Paths() {
			os.Remove(fp)
		}

		// we remove only empty directories
		for _, dir := range c.ExpandedDir() {
			os.Remove(dir)
		}

		// we remove directory which have been created
		for _, i := range *(c.createdDir.List()) {
			dir := i.(string)
			os.RemoveAll(dir)
		}
	}
}

func (c *Canary) Paths() (files []string) {
	files = make([]string, 0, len(c.Files)*len(c.Directories))
	for _, dir := range c.ExpandedDir() {
		for _, fn := range c.Files {
			files = append(files, filepath.Join(dir, fn))
		}
	}
	return
}

type CanariesConfig struct {
	Enable    bool      `toml:"enable" comment:"Enable canary files management"`
	Actions   []string  `toml:"actions" comment:"Actions to apply when a canary file is touched"`
	Whitelist []string  `toml:"whitelist" comment:"Process images being allowed to touch the canaries"`
	Canaries  []*Canary `toml:"canaries" comment:"Canary files to create at every run"`
}

func (c *CanariesConfig) Initialize() {
	auditDirs := make([]string, 0)
	if c.Enable {
		for _, cf := range c.Canaries {
			// add the list of directories to audit
			if cf.SetAuditACL {
				auditDirs = append(auditDirs, cf.ExpandedDir()...)
			}

			if err := cf.Create(); err != nil {
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

func (c *CanariesConfig) RestoreACLs() {
	auditDirs := make([]string, 0)
	for _, cf := range c.Canaries {
		// add the list of directories to audit
		if cf.SetAuditACL {
			auditDirs = append(auditDirs, cf.ExpandedDir()...)
		}
	}
	if err := utils.RemoveEDRAuditACL(auditDirs...); err != nil {
		log.Errorf("Error while setting canaries' Audit ACLs: %s", err)
	}
}

func (c *CanariesConfig) Clean() {
	if c.Enable {
		for _, cf := range c.Canaries {
			cf.Clean()
		}
	}
}

func (c *CanariesConfig) CanaryRegexp() string {
	repaths := make([]string, 0)
	for _, c := range c.Canaries {

		// adding list of created dir
		for _, i := range *(c.createdDir.List()) {
			dir := fmt.Sprintf("%s%c", i.(string), os.PathSeparator)
			repaths = append(repaths, regexp.QuoteMeta(dir))
		}

		for _, fp := range c.Paths() {
			dir := filepath.Dir(fp)
			if !c.createdDir.Contains(dir) {
				repaths = append(repaths, regexp.QuoteMeta(fp))
			}
		}
	}
	return fmt.Sprintf("(?i:(%s))", strings.Join(repaths, "|"))
}

func (c *CanariesConfig) WhitelistRegexp() string {
	wl := make([]string, 0, len(c.Whitelist))
	for _, im := range c.Whitelist {
		wl = append(wl, regexp.QuoteMeta(im))
	}
	return fmt.Sprintf("(?i:(%s))", strings.Join(wl, "|"))
}

func (c *CanariesConfig) GenRuleFSAudit() (r rules.Rule) {
	r = rules.NewRule()
	r.Name = "Builtin:CanaryAccessed"
	r.Meta.EventIDs = []int64{4663}
	r.Meta.Channels = []string{
		"Security",
	}
	r.Meta.Criticality = 10
	r.Matches = []string{
		"$access: AccessMask &= '0x1'",
		fmt.Sprintf("$wl_images: ProcessName ~= '%s'", c.WhitelistRegexp()),
		fmt.Sprintf("$canary: ObjectName ~= '%s'", c.CanaryRegexp()),
	}
	r.Condition = "!$wl_images and $access and $canary"
	r.Actions = append(r.Actions, c.Actions...)
	return
}

func (c *CanariesConfig) GenRuleSysmon() (r rules.Rule) {
	r = rules.NewRule()
	r.Name = "Builtin:CanaryModified"
	// FileCreate, FileDeleted and FileDeletedDetected
	r.Meta.EventIDs = []int64{11, 23, 26}
	r.Meta.Channels = []string{
		"Microsoft-Windows-Sysmon/Operational",
	}
	r.Meta.Criticality = 10
	r.Matches = []string{
		fmt.Sprintf("$wl_images: Image ~= '%s'", c.WhitelistRegexp()),
		fmt.Sprintf("$canary: TargetFilename ~= '%s'", c.CanaryRegexp()),
	}
	r.Condition = "!$wl_images and $canary"
	r.Actions = append(r.Actions, c.Actions...)
	return
}
