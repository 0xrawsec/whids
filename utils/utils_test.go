package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/los"
	"github.com/pelletier/go-toml/v2"
)

var (
	pid = 604
)

var (
	format = fmt.Sprintf
)

func TestIsValidUUID(t *testing.T) {
	tt := toast.FromT(t)

	for i := 0; i < 1000; i++ {
		uuid := UUIDOrPanic().String()
		tt.Assert(IsValidUUID(uuid))
		tt.Assert(!IsValidUUID(format("%s42", uuid)))
		tt.Assert(!IsValidUUID(format("42%s", uuid)))
	}
}

type testStruct struct {
	F []string
}

func controlHashStability(t *testing.T, test testStruct) (hash string) {
	var err error
	tt := toast.FromT(t)

	hash, err = Sha256Interface(test)
	tt.CheckErr(err)

	tomls, err := Toml(test)
	tt.CheckErr(err)
	toml.Unmarshal(tomls, &test)
	//new, err := Sha256Interface(test)
	new, err := Sha256Interface(test)
	tt.CheckErr(err)

	tt.Assert(hash == new)
	return
}

func TestSha256Interface(t *testing.T) {
	tt := toast.FromT(t)

	test := testStruct{}
	initTest := testStruct{[]string{"test", "toast"}}
	//h, err := Sha256Interface(test)
	hashEmpty := controlHashStability(t, test)
	hashInit := controlHashStability(t, initTest)

	tt.Assert(hashEmpty != hashInit)
}

func TestExpandEnvs(t *testing.T) {
	var envs []string

	tt := toast.FromT(t)

	switch los.OS {
	case los.OSWindows:
		envs = []string{"$Systemroot", "$systemdrive", "$programfiles", "$localappdata"}
	default:
		envs = []string{"$HOME", "$PWD"}
	}

	for i, exp := range ExpandEnvs(envs...) {
		t.Logf("%s=%s", envs[i], exp)
		tt.Assert(exp != "", fmt.Sprintf("failed to resolve environment variable %s", envs[i]))
		tt.Assert(fsutil.Exists(exp))
	}
}

func TestSha256StringSlice(t *testing.T) {
	t.Parallel()

	var s []string

	tt := toast.FromT(t)

	h := sha256.New()

	for i := 0; i < 100; i++ {
		k := NewKeyOrPanic(50)
		s = append(s, k)
		h.Write([]byte(k))
	}

	tt.Assert(Sha256StringSlice(s) == hex.EncodeToString(h.Sum(nil)))
}

func TestDedupStringSlice(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	s := []string{
		"test",
		"test",
		"toast",
		"toast",
		"roast",
	}

	dedup := DedupStringSlice(s)

	tt.Assert(len(dedup) == 3)
	tt.Assert(dedup[0] == "test")
	tt.Assert(dedup[1] == "toast")
	tt.Assert(dedup[2] == "roast")
}

func TestRound(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	tt.Assert(fmt.Sprintf("%.2f", Round(1.6333333, 2)) == "1.63")
	tt.Assert(fmt.Sprintf("%.2f", Round(1.6555555, 2)) == "1.65")
	tt.Assert(fmt.Sprintf("%.2f", Round(1.6666666, 2)) == "1.67")
}

func TestUtf16ToUtf8(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	utf16 := []byte{255, 254, 13, 0, 10, 0, 13, 0, 10, 0, 32, 0, 32, 0, 32, 0, 32, 0, 68, 0, 105, 0, 114, 0, 101, 0, 99, 0, 116, 0, 111, 0, 114, 0, 121, 0, 58, 0, 32, 0, 67, 0, 58, 0, 92, 0, 13, 0, 10, 0, 13, 0, 10, 0, 13, 0, 10, 0, 77, 0, 111, 0, 100, 0, 101, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 76, 0, 97, 0, 115, 0, 116, 0, 87, 0, 114, 0, 105, 0, 116, 0, 101, 0, 84, 0, 105, 0, 109, 0, 101, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 76, 0, 101, 0, 110, 0, 103, 0, 116, 0, 104, 0, 32, 0, 78, 0, 97, 0, 109, 0, 101, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 13, 0, 10, 0}

	utf8, err := Utf16ToUtf8(utf16)

	tt.CheckErr(err)
	// we have to take BOM into account for length caculation
	tt.Assert(len(utf8) == (len(utf16)-2)/2)

	t.Log(string(utf8))

}
