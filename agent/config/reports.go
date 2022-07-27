package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/0xrawsec/whids/tools"
)

// ReportCommand is a structure both to configure commands to run in a report
// but also to store the outcome of the command after it ran
type ReportCommand struct {
	Description string        `json:"description" toml:"description" comment:"Description of the command to run, for reporting purposes"`
	Name        string        `json:"name" toml:"name" comment:"Name of the command to execute (can be a binary)"`
	Args        []string      `json:"args" toml:"args" comment:"Argument of the command line"`
	ExpectJSON  bool          `json:"expect-json" toml:"expect-json" comment:"Expect JSON formated output on stdout"`
	Stdout      interface{}   `json:"stdout" toml:",omitempty"`
	Stderr      []byte        `json:"stderr" toml:",omitempty"`
	Error       string        `json:"error" toml:",omitempty"`
	Timestamp   time.Time     `json:"timestamp" toml:",omitempty"`
	Timeout     time.Duration `json:"timeout" toml:"timeout" comment:"Timeout to apply to the command (if > 0 this takes precedence over the global report timeout setting)"`
}

// Run the desired command
func (c *ReportCommand) Run() {
	var cmd *exec.Cmd
	var err error
	var stdout []byte
	var cancel context.CancelFunc

	ctx := context.Background()
	if c.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), c.Timeout)
		defer cancel()
	}

	cmd = exec.CommandContext(ctx, c.Name, c.Args...)
	// set timestamp
	c.Timestamp = time.Now()
	if stdout, err = cmd.Output(); err != nil {
		c.Error = err.Error()
		if ee, ok := err.(*exec.ExitError); ok {
			c.Stderr = ee.Stderr
		}
	}

	if c.ExpectJSON {
		if err = json.Unmarshal(stdout, &(c.Stdout)); err != nil {
			c.Stdout = string(stdout)
			c.Error = err.Error()
		}
	} else {
		c.Stdout = stdout
	}
}

var (
	osqueryiArgs = []string{"--json", "-A"}
)

// OSQuery holds configuration about OSQuery tool
type OSQuery struct {
	Tables []string `json:"tables" toml:"tables" comment:"OSQuery tables to add to the report"`
}

// PrepareCommands builds up osquery commands
func (c *OSQuery) PrepareCommands() (cmds []ReportCommand) {
	cmds = make([]ReportCommand, len(c.Tables))

	for i, t := range c.Tables {
		cmds[i].Description = fmt.Sprintf("OSQuery %s table", t)
		cmds[i].Name = tools.ToolOSQueryi
		cmds[i].Args = osqueryiArgs
		cmds[i].Args = append(cmds[i].Args, t)

		cmds[i].ExpectJSON = true
	}

	return
}

// Report holds report configuration
type Report struct {
	EnableReporting bool            `json:"en-reporting" toml:"en-reporting" comment:"Enables IR reporting"`
	OSQuery         OSQuery         `json:"osquery" toml:"osquery" comment:"OSQuery configuration"`
	Commands        []ReportCommand `json:"commands" toml:"commands" comment:"Commands to execute in addition to the OSQuery ones" commented:"true"`
	CommandTimeout  time.Duration   `json:"timeout" toml:"timeout" comment:"Timeout after which every command expires (to prevent too long commands)"`
}

// PrepareCommands builds up all commands to run
func (c *Report) PrepareCommands() (cmds []ReportCommand) {

	cmds = make([]ReportCommand, 0, len(c.OSQuery.Tables)+len(c.Commands))
	// OSQuery commands processed first
	for _, rc := range c.OSQuery.PrepareCommands() {
		rc.Timeout = c.CommandTimeout
		cmds = append(cmds, rc)
	}

	// other commands
	for _, rc := range c.Commands {
		if rc.Timeout == 0 {
			rc.Timeout = c.CommandTimeout
		}
		cmds = append(cmds, rc)
	}
	return
}
