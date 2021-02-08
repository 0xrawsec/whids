package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/shlex"
	"github.com/google/uuid"
)

// Endpoint structure used to track and interact with endpoints
type Endpoint struct {
	UUID           string    `json:"uuid"`
	Hostname       string    `json:"hostname"`
	IP             string    `json:"ip"`
	Key            string    `json:"key"`
	Command        *Command  `json:"command,omitempty"`
	LastConnection time.Time `json:"last-connection"`
}

// NewEndpoint returns a new Endpoint structure
func NewEndpoint(uuid, key string) *Endpoint {
	return &Endpoint{UUID: uuid, Key: key}
}

// Copy returns a pointer to a new copy of the Endpoint
func (e *Endpoint) Copy() *Endpoint {
	new := *e
	return &new
}

// UpdateLastConnection updates the LastConnection member of Endpoint structure
func (e *Endpoint) UpdateLastConnection() {
	e.LastConnection = time.Now()
}

// EndpointFile describes a File to drop or fetch from the endpoint
type EndpointFile struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Data  []byte `json:"data"`
	Error string `json:"error"`
}

// Command structure representing a command sent to an endpoint
type Command struct {
	UUID string   `json:"uuid"`
	Name string   `json:"name"`
	Args []string `json:"args"`
	// used to drop files on the endpoint
	Drop []*EndpointFile `json:"drop"`
	// used to fetch files from the endpoint
	Fetch      map[string]*EndpointFile `json:"fetch"`
	Stdout     []byte                   `json:"stdout"`
	Stderr     []byte                   `json:"stderr"`
	Error      string                   `json:"error"`
	Sent       bool                     `json:"sent"`
	Background bool                     `json:"background"`
	Completed  bool                     `json:"completed"`
	Timeout    time.Duration            `json:"timeout"`
	SentTime   time.Time                `json:"sent-time"`
	aliasEnv   *AliasEnv
}

// NewCommand creates a new Command to run on an endpoint
func NewCommand() *Command {
	id := CheapUUID()
	cmd := &Command{
		UUID:  id.String(),
		Drop:  make([]*EndpointFile, 0),
		Fetch: make(map[string]*EndpointFile)}
	return cmd
}

// NewCommandWithEnv creates a new Command to run on an endpoint
func NewCommandWithEnv(env *AliasEnv) *Command {
	id := CheapUUID()
	cmd := &Command{
		UUID:     id.String(),
		Drop:     make([]*EndpointFile, 0),
		Fetch:    make(map[string]*EndpointFile),
		aliasEnv: env}
	return cmd
}

// SetCommandLine sets the command line to execute on the endpoint
func (c *Command) SetCommandLine(cl string) error {
	args, err := shlex.Split(cl)
	if err != nil {
		return fmt.Errorf("failed to parse command line: %w", err)
	}

	if len(args) > 0 {
		c.Name = args[0]
	}
	if len(args) > 1 {
		c.Args = args[1:]
	}
	return nil
}

// AddDropFile adds a file to drop on the endpoint. Argument filepath
// is the path of the file on the local filesystem
func (c *Command) AddDropFile(filename, filepath string) error {
	var err error

	ef := EndpointFile{
		UUID: CheapUUID().String(),
		Name: filename}
	if ef.Data, err = ioutil.ReadFile(filepath); err != nil {
		return fmt.Errorf("failed at reading file to drop: %w", err)
	}

	c.Drop = append(c.Drop, &ef)

	return nil
}

// AddDropFileFromPath adds a file to drop on the endpoint. It
// is a wrapper around AddDropFile
func (c *Command) AddDropFileFromPath(path string) error {
	return c.AddDropFile(filepath.Base(path), path)
}

// AddFetchFile adds a file to fetch from the endpoint.
func (c *Command) AddFetchFile(filepath string) {
	c.Fetch[filepath] = &EndpointFile{UUID: CheapUUID().String()}
}

// BuildCmd builds up an exec.Cmd from Command
func (c *Command) BuildCmd() (*exec.Cmd, error) {
	switch c.Name {
	case "contain":
		if cmd := ContainAlias(c.aliasEnv.ManagerIP); cmd != nil {
			return cmd, nil
		}
		return nil, fmt.Errorf("Bad manager IP")
	case "uncontain":
		return UncontainAlias(), nil
	default:
		if c.Timeout > 0 {
			// we create a command with a timeout context if needed
			ctx, _ := context.WithTimeout(context.Background(), c.Timeout)
			return exec.CommandContext(ctx, c.Name, c.Args...), nil
		}
		return exec.Command(c.Name, c.Args...), nil
	}
}

// Run runs the command according to the specified settings
// it aims at being used on the endpoint
func (c *Command) Run() (err error) {
	// current working directory for command
	var cwd string
	var cmd *exec.Cmd

	// if we want to execute a binary
	if len(c.Drop) > 0 {
		// genererating random uuid to drop binary in
		randDir, err := uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("failed to create random directory: %w", err)
		}

		// creating temporary directory
		tmpDir := filepath.Join(os.TempDir(), randDir.String())
		if err := os.MkdirAll(tmpDir, 0700); err != nil {
			return fmt.Errorf("failed to create temporary directory: %w", err)
		}

		// dropping files before command is run so that we can used
		// dropped files as arguments to the command line
		for _, ef := range c.Drop {
			binPath := filepath.Join(tmpDir, ef.Name)
			err := ioutil.WriteFile(binPath, ef.Data, 0700)
			if err != nil {
				ef.Error = fmt.Sprintf("%s", err)
			}
		}

		// current working directory is where we dropped files
		cwd = tmpDir

		// remove temporary directory after Run is finished
		defer os.RemoveAll(tmpDir)
	}

	// we have something to run
	if c.Name != "" {
		cmd, err = c.BuildCmd()
		if err == nil {
			c.Name = cmd.Path
			c.Args = cmd.Args
			// if we dropped a binary we use the relative directory as working directory
			if cwd != "" {
				cmd.Dir = cwd
			}

			// we run the command and wait for its output
			stdout, err := cmd.Output()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					c.Stderr = ee.Stderr
				}
				c.Error = fmt.Sprintf("%s", err)
			}
			c.Stdout = stdout
		} else {
			// if we failed to build the command we set error field
			c.Error = fmt.Sprintf("Failed to build command: %s", err)
		}
	}

	// fetching files after the command has been ran
	for fn := range c.Fetch {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			c.Fetch[fn].Error = fmt.Sprintf("%s", err)
		}
		c.Fetch[fn].Data = data
	}

	return
}

func (c Command) String() string {
	return fmt.Sprintf("%s %s", c.Name, c.Args)
}

// Strip reduces the command to the strict necessary fields
// to make the return trip from the endpoint to the manager
func (c *Command) Strip() {
	//c.Name = ""
	//c.Args = nil
	for _, ef := range c.Drop {
		ef.Data = nil
	}
}

// Complete updates a command from another
func (c *Command) Complete(other *Command) error {
	if c.UUID == other.UUID {
		c.Name = other.Name
		c.Args = other.Args
		c.Stdout = other.Stdout
		c.Stderr = other.Stderr
		c.Error = other.Error
		c.Drop = other.Drop
		c.Fetch = other.Fetch
		c.Completed = true
		return nil
	}
	return fmt.Errorf("Commands do not have the same ID")
}

////////////// Builtin commands

// derived from: https://gist.github.com/kotakanbe/d3059af990252ba89a82
func next(ip net.IP) net.IP {
	nip := net.IP(make(net.IP, len(ip)))
	copy(nip, ip)
	for j := len(nip) - 1; j >= 0; j-- {
		nip[j]++
		if nip[j] > 0 {
			break
		}
	}
	return nip
}

// derived from: https://gist.github.com/kotakanbe/d3059af990252ba89a82
func prev(ip net.IP) net.IP {
	nip := net.IP(make(net.IP, len(ip)))
	copy(nip, ip)
	for j := len(nip) - 1; j >= 0; j-- {
		nip[j]--
		if nip[j] < 255 {
			break
		}
	}
	return nip
}

const (
	ContainRuleName = "EDR containment"
)

type AliasEnv struct {
	ManagerIP net.IP
}

func ContainAlias(ip net.IP) *exec.Cmd {
	if ip != nil {
		ip = ip.To4()
		// building up netsh.exe arguments
		args := []string{
			"advfirewall",
			"firewall",
			"add",
			"rule",
			fmt.Sprintf("name=%s", ContainRuleName),
			"dir=out",
			fmt.Sprintf("remoteip=0.0.0.0-%s,%s-255.255.255.255", prev(ip), next(ip)),
			"action=block",
		}
		return exec.Command("netsh.exe", args...)
	}
	return nil
}

func UncontainAlias() *exec.Cmd {
	// building up netsh.exe arguments
	args := []string{"advfirewall",
		"firewall",
		"delete",
		"rule",
		fmt.Sprintf("name=%s", ContainRuleName),
	}
	return exec.Command("netsh.exe", args...)
}
