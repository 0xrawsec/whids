package command

import (
	"os/exec"
	"testing"
	"time"

	"github.com/0xrawsec/toast"
)

func TestCommandeTimeout(t *testing.T) {
	tt := toast.FromT(t)

	c := CommandTimeout(1*time.Second, "yes")
	defer c.Terminate()
	tt.ExpectErr(c.Run(), &exec.ExitError{})

	c = Command("yes")
	tt.CheckErr(c.Start())
	c.Terminate()
	tt.ExpectErr(c.Wait(), &exec.ExitError{})
}
