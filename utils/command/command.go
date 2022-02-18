package command

import (
	"context"
	"os/exec"
	"time"
)

type Cmd struct {
	*exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
}

func Command(name string, arg ...string) (c *Cmd) {
	c = &Cmd{}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.Cmd = exec.CommandContext(c.ctx, name, arg...)
	return
}

func CommandTimeout(timeout time.Duration, name string, arg ...string) (c *Cmd) {
	c = &Cmd{}
	c.ctx, c.cancel = context.WithTimeout(context.Background(), timeout)
	c.Cmd = exec.CommandContext(c.ctx, name, arg...)
	return
}

func (c *Cmd) Terminate() {
	if c.cancel != nil {
		c.cancel()
	}
}
