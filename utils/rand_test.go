package utils

import (
	"testing"

	"github.com/0xrawsec/toast"
)

func TestRand(t *testing.T) {
	tt := toast.FromT(t)

	t.Log(UnsafeUUID().String())
	t.Log(UUIDOrPanic().String())
	uuid, err := NewUUIDString()
	tt.CheckErr(err)
	t.Log(uuid)
	tt.Assert(len(NewKeyOrPanic(32)) == 32)
	tt.Assert(len(NewKeyOrPanic(42)) == 42)
	tt.Assert(len(NewKeyOrPanic(4242)) == 4242)

	uuid, key, err := UUIDKeyPair(42)
	tt.CheckErr(err)
	tt.Assert(len(key) == 42)
	t.Log(uuid)
}
