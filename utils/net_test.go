package utils

import (
	"net"
	"testing"

	"github.com/0xrawsec/toast"
)

func TestPrevNextIP(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	ip := net.ParseIP("192.168.1.42")
	tt.Assert(PrevIP(ip).String() == "192.168.1.41")
	tt.Assert(NextIP(ip).String() == "192.168.1.43")
}
