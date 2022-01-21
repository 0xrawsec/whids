package sysinfo

import (
	"testing"

	"github.com/0xrawsec/whids/utils"
)

func TestSystemInfo(t *testing.T) {
	var h string
	var err error
	info := NewSystemInfo()
	if h, err = utils.HashStruct(info); err != nil {
		t.Error(err)
	}
	t.Log(utils.PrettyJson(info))
	t.Logf("Structure hash: %s", h)
	for i := 0; i < 1000; i++ {
		if n, err := utils.HashStruct(info); err != nil {
			t.Error(err)
			t.FailNow()
		} else if n != h {
			t.Error("hash function is not stable")
		}
	}
}
