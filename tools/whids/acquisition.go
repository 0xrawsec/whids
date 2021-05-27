package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/shlex"
)

type ReportCommand struct {
	Description string `toml:"description" comment:"Description of the command to run, for reporting purposes"`
	CommandLine string `toml:"cmd-line" comment:"Command line to be executed"`
	ExpectJSON  bool
	Stdout      interface{}
	Stderr      []byte
	Timeout     time.Duration
}

func (c *ReportCommand) Run() {
	var cmd *exec.Cmd
	args := make([]string, 0)
	stdout := make([]byte, 0)

	if cl, err := shlex.Split(c.CommandLine); err == nil {
		ctx := context.Background()
		if c.Timeout > 0 {
			ctx, _ = context.WithTimeout(context.Background(), c.Timeout)
		}
		if len(cl) > 0 {
			if len(cl) > 1 {
				args = append(args, cl[1:]...)
			}

			cmd = exec.CommandContext(ctx, cl[0], args...)
			if stdout, err = cmd.Output(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					c.Stderr = ee.Stderr
				}
			}

			if c.ExpectJSON {
				c.Stdout = string(stdout)
			}
		}
	}
}

type OSQueryConfig struct {
	Bin    string   `toml:"bin" comment:"Path to osqueryi binary"`
	Tables []string `toml:"tables" comment:"OSQuery tables to add to the report"`
}

const (
	osqueryiArgs = "--json -A %s"
)

func (c *OSQueryConfig) Commands() (cmds []ReportCommand) {
	cmds = make([]ReportCommand, len(c.Tables))

	for i, t := range c.Tables {
		args := fmt.Sprintf(osqueryiArgs, t)
		cmds[i].CommandLine = fmt.Sprintf("%s %s", c.Bin, args)
		cmds[i].ExpectJSON = true
	}

	return
}

type IRReportConfig struct {
	EnableReporting bool            `toml:"en-reporting" comment:"Enables IR reporting"`
	OSQuery         OSQueryConfig   `toml:"osquery-config" comment:"OSQuery configuration"`
	Commands        []ReportCommand `toml:"acqu-commands" comment:"Acquisition commands to execute in addition to the OSQuery ones"`
	CommandTimeout  time.Duration   `toml:"timeout" comment:"Timeout after which every command expires (to prevent too long commands)"`
}

func (c *IRReportConfig) AllCommands() (cmds []ReportCommand) {

	cmds = make([]ReportCommand, 0, len(c.OSQuery.Tables)+len(c.Commands))
	// OSQuery commands processed first
	for _, rc := range c.OSQuery.Commands() {
		cmds = append(cmds, rc)
	}

	// other commands
	for _, rc := range c.Commands {
		cmds = append(cmds, rc)
	}
	return
}

func Report(c *IRReportConfig) (r []ReportCommand) {
	r = c.AllCommands()
	for i := range r {
		r[i].Run()
	}
	return
}
