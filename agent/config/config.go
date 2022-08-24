package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/api/client/config"
	"github.com/0xrawsec/whids/utils"
	"github.com/pelletier/go-toml"
)

const (
	// default action lower and upper bounds
	ActionLowLow, ActionLowHigh           = 1, 4
	ActionMediumLow, ActionMediumHigh     = 5, 7
	ActionHighLow, ActionHighHigh         = 8, 9
	ActionCriticalLow, ActionCriticalHigh = 10, 10
)

var (
	emptyForwarderConfig = config.Forwarder{}
)

type Actions struct {
	AvailableActions []string `json:"available-actions" toml:"available-actions" commented:"true" comment:"List of available actions (here as a memo for easier configuration, but it is not used in any way by the engine)"`
	Low              []string `json:"low" toml:"low" comment:"Default actions to be taken when event criticality is in [1; 4]"`
	Medium           []string `json:"medium" toml:"medium" comment:"Default actions to be taken when event criticality is in [5; 7]"`
	High             []string `json:"high" toml:"high" comment:"Default actions to be taken when event criticality is in [8; 9]"`
	Critical         []string `json:"critical" toml:"critical" comment:"Default actions to be taken when event criticality is 10"`
}

// Dump structure definition
type Dump struct {
	Dir           string `json:"dir" toml:"dir" comment:"Directory used to store dumps"`
	MaxDumps      int    `json:"max-dumps" toml:"max-dumps" comment:"Maximum number of dumps per process"` // maximum number of dump per GUID
	Compression   bool   `json:"compression" toml:"compression" comment:"Enable dumps compression"`
	DumpUntracked bool   `json:"dump-untracked" toml:"dump-untracked" comment:"Dumps untracked process. Untracked processes are missing\n enrichment information and may generate unwanted dumps"` // whether or not we should dump untracked processes, if true it would create many FPs
}

// Sysmon holds Sysmon related configuration
type Sysmon struct {
	Bin              string `json:"bin" toml:"bin" comment:"Path to Sysmon binary"`
	ArchiveDirectory string `json:"archive-directory" toml:"archive-directory" comment:"Path to Sysmon Archive directory"`
	CleanArchived    bool   `json:"clean-archived" toml:"clean-archived" comment:"Delete files older than 5min archived by Sysmon"`
}

// Rules holds rules configuration
type Rules struct {
	RulesDB        string        `json:"rules-db" toml:"rules-db" comment:"Path to Gene rules database"`
	ContainersDB   string        `json:"containers-db" toml:"containers-db" comment:"Path to Gene rules containers\n (c.f. Gene documentation)"`
	UpdateInterval time.Duration `json:"update-interval" toml:"update-interval" comment:"Update interval at which rules should be pulled from manager\n NB: only applies if a manager server is configured"`
}

func (c *Rules) RulesPaths() (path, sha256Path string) {
	path = filepath.Join(c.RulesDB, "database.gen")
	sha256Path = fmt.Sprintf("%s.sha256", path)
	return
}

// Audit holds Windows audit configuration
type Audit struct {
	Enable        bool     `json:"enable" toml:"enable" comment:"Enable following Audit Policies or not"`
	AuditPolicies []string `json:"audit-policies" toml:"audit-policies" comment:"Audit Policies to enable (c.f. auditpol /get /category:* /r)"`
	AuditDirs     []string `json:"audit-dirs" toml:"audit-dirs" comment:"Set Audit ACL to directories, sub-directories and files to generate File System audit events\n https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system)"`
}

// Configure configures the desired audit policies
func (c *Audit) Configure() {

	if c.Enable {
		for _, ap := range c.AuditPolicies {
			if err := utils.EnableAuditPolicy(ap); err != nil {
				log.Errorf("Failed to enable audit policy %s: %s", ap, err)
			} else {
				log.Infof("Enabled Audit Policy: %s", ap)
			}
		}
	}

	// run this function async as it might take a little bit of time
	go func() {
		dirs := utils.StdDirs(utils.ExpandEnvs(c.AuditDirs...)...)
		if len(dirs) > 0 {
			log.Infof("Setting ACLs for directories: %s", strings.Join(dirs, ", "))
			if err := utils.SetEDRAuditACL(dirs...); err != nil {
				log.Errorf("Error while setting configured File System Audit ACLs: %s", err)
			}
			log.Infof("Finished setting up ACLs for directories: %s", strings.Join(dirs, ", "))
		}
	}()
}

// Restore the audit policies
func (c *Audit) Restore() {
	for _, ap := range c.AuditPolicies {
		if err := utils.DisableAuditPolicy(ap); err != nil {
			log.Errorf("Failed to disable audit policy %s: %s", ap, err)
		}
	}

	dirs := utils.StdDirs(utils.ExpandEnvs(c.AuditDirs...)...)
	if err := utils.RemoveEDRAuditACL(dirs...); err != nil {
		log.Errorf("Error while restoring File System Audit ACLs: %s", err)
	}
}

// Agent structure
type Agent struct {
	path string

	DatabasePath    string           `json:"db-path" toml:"db-path" comment:"Path to local database root directory"`
	CritTresh       int              `json:"criticality-treshold" toml:"criticality-treshold" comment:"Dumps/forward only events above criticality threshold\n or filtered events (i.e. Gene filtering rules)" `
	EnableHooks     bool             `json:"en-hooks" toml:"en-hooks" comment:"Enable enrichment hooks and dump hooks"`
	EnableFiltering bool             `json:"en-filters" toml:"en-filters" comment:"Enable event filtering (log filtered events, not only alerts)\n See documentation: https://github.com/0xrawsec/gene" `
	Logfile         string           `json:"logfile" toml:"logfile" comment:"Logfile used to log messages generated by the engine"` // for WHIDS log messages (not alerts)
	LogAll          bool             `json:"log-all" toml:"log-all" comment:"Log any incoming event passing through the engine" `   // log all events to logfile (used for debugging)
	Endpoint        bool             `json:"endpoint" toml:"endpoint" comment:"True if current host is the endpoint on which logs are generated\n Example: turn this off if running on a WEC"`
	EtwConfig       Etw              `json:"etw" toml:"etw" comment:"ETW configuration"`
	FwdConfig       config.Forwarder `json:"forwarder" toml:"forwarder" comment:"Forwarder configuration"`
	Sysmon          Sysmon           `json:"sysmon" toml:"sysmon" comment:"Sysmon related settings"`
	Actions         Actions          `json:"actions" toml:"actions" comment:"Default actions to apply to events, depending on their criticality"`
	Dump            Dump             `json:"dump" toml:"dump" comment:"Dump related settings"`
	Report          Report           `json:"report" toml:"reporting" comment:"Reporting related settings"`
	RulesConfig     Rules            `json:"rules" toml:"rules" comment:"Gene rules related settings\n Gene repo: https://github.com/0xrawsec/gene\n Gene rules repo: https://github.com/0xrawsec/gene-rules"`
	AuditConfig     Audit            `json:"audit" toml:"audit" comment:"Windows auditing configuration"`
	CanariesConfig  Canaries         `json:"canaries" toml:"canaries" comment:"Canary files configuration"`
}

// LoadAgentConfig loads a HIDS configuration from a file
func LoadAgentConfig(path string) (c Agent, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return
	}
	defer fd.Close()
	dec := toml.NewDecoder(fd)
	err = dec.Decode(&c)
	c.path = path
	return
}

func (c *Agent) Sha256() (string, error) {
	return utils.Sha256Interface(c)
}

// IsForwardingEnabled returns true if a forwarder is actually configured to forward logs
func (c *Agent) IsForwardingEnabled() bool {
	return c.FwdConfig != emptyForwarderConfig && !c.FwdConfig.Local
}

// Prepare creates directory used in the config if not existing
func (c *Agent) Prepare() {
	if !fsutil.Exists(c.RulesConfig.RulesDB) {
		os.MkdirAll(c.RulesConfig.RulesDB, 0600)
	}

	if !fsutil.Exists(c.RulesConfig.ContainersDB) {
		os.MkdirAll(c.RulesConfig.ContainersDB, 0600)
	}

	if !fsutil.Exists(c.Dump.Dir) {
		os.MkdirAll(c.Dump.Dir, 0600)
	}

	if !fsutil.Exists(filepath.Dir(c.FwdConfig.Logging.Dir)) {
		os.MkdirAll(filepath.Dir(c.FwdConfig.Logging.Dir), 0600)
	}

	if !fsutil.Exists(filepath.Dir(c.Logfile)) {
		os.MkdirAll(filepath.Dir(c.Logfile), 0600)
	}
}

// Verify validate HIDS configuration object
func (c *Agent) Verify() error {
	if !fsutil.IsDir(c.RulesConfig.RulesDB) {
		return fmt.Errorf("rules database must be a directory")
	}
	if !fsutil.IsDir(c.RulesConfig.ContainersDB) {
		return fmt.Errorf("containers database must be a directory")
	}
	return nil
}

func (c *Agent) Path() string {
	return c.path
}

// Save saves configuration to path
func (c *Agent) Save(path string) (err error) {
	var b []byte

	if b, err = utils.Json(c); err != nil {
		return
	}

	return utils.HidsWriteData(path, b)
}
