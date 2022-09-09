package utils

import (
	"fmt"
	"testing"

	"github.com/0xrawsec/toast"
	"github.com/pelletier/go-toml/v2"
)

var (
	pid = 604
)

func TestRegQuery(t *testing.T) {
	/*path := `HKLM\System\CurrentControlSet\Services\SysmonDrv\Parameters\HashingAlgorithm`
	key, value := filepath.Split(path)
	t.Logf("Sysmon hashing algorithm: %s", RegQuery(key, value))*/
}

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
