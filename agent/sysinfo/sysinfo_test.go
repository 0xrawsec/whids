package sysinfo

import (
	"reflect"
	"testing"

	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/utils"
)

func TestSystemInfo(t *testing.T) {
	t.Parallel()

	var h string
	var err error

	tt := toast.FromT(t)
	ei := &EdrInfo{
		Version: "major.minor.patch",
		Commit:  "somerandomcommitid",
	}

	info := NewSystemInfo()
	tt.Assert(edrInfo == nil)
	tt.Assert(info.Edr == nil)

	// we register edr information
	RegisterEdrInfo(ei)
	tt.Assert(edrInfo != nil)
	tt.Assert(reflect.DeepEqual(edrInfo, ei))

	info = NewSystemInfo()
	tt.Assert(reflect.DeepEqual(info.Edr, ei))

	if h, err = utils.Sha1Interface(info); err != nil {
		t.Error(err)
	}
	t.Log(utils.PrettyJsonOrPanic(info))
	t.Logf("Structure hash: %s", h)
	for i := 0; i < 1000; i++ {
		if n, err := utils.Sha1Interface(info); err != nil {
			t.Error(err)
			t.FailNow()
		} else if n != h {
			t.Error("hash function is not stable")
		}
	}
}
