package command

import (
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/0xrawsec/toast"
)

func TestCommandTimeout(t *testing.T) {
	var name string

	args := make([]string, 0)

	tt := toast.FromT(t)

	switch runtime.GOOS {
	case "windows":
		name = "cmd"
		args = append(args, "/c", "timeout", "30")
	case "linux":
		name = "yes"
	}

	c := CommandTimeout(1*time.Second, name, args...)
	defer c.Terminate()
	err := c.Run()
	_, ok := err.(*exec.ExitError)
	tt.Assert(ok)

	c = Command(name, args...)
	tt.CheckErr(c.Start())
	c.Terminate()
	err = c.Wait()
	_, ok = err.(*exec.ExitError)
	tt.Assert(ok)
}
