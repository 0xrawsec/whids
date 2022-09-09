package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
)

var (
	RegexUuid = regexp.MustCompile(`^(?i:[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})$`)
)

func IsValidUUID(uuid string) bool {
	return RegexUuid.MatchString(uuid)
}

// ExpandEnvs expands several strings with environment variable
// it is just a loop calling os.ExpandEnv for every element
func ExpandEnvs(s ...string) (o []string) {
	o = make([]string, len(s))
	for i := range s {
		o[i] = os.ExpandEnv(s[i])
	}
	return
}

func gobBytes(i any) (b []byte, err error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)

	err = enc.Encode(i)
	b = buf.Bytes()

	return
}

// Sha256StringArray utility
func Sha256StringArray(array []string) string {
	sha256 := sha256.New()
	for _, e := range array {
		sha256.Write([]byte(e))
	}
	return hex.EncodeToString(sha256.Sum(nil))
}

// HashEventBytes return a hash from a byte slice assuming
// the event has been JSON encoded with the json.Marshal
func Sha1EventBytes(b []byte) string {
	return data.Sha1(bytes.Trim(b, " \n\r\t"))
}

func Sha256Interface(i interface{}) (h string, err error) {
	var b []byte

	if b, err = gobBytes(i); err != nil {
		return
	}

	return data.Sha256(b), nil
}

func GetCurFuncName() string {
	if pc, _, _, ok := runtime.Caller(1); ok {
		split := strings.Split(runtime.FuncForPC(pc).Name(), "/")
		return split[len(split)-1]
	}
	return "unk.UnknownFunc"
}

func DedupStringSlice(in []string) (out []string) {
	s := datastructs.NewSet()
	for _, v := range in {
		if !s.Contains(v) {
			out = append(out, v)
			s.Add(v)
		}
	}
	return
}

// Round float f to precision
func Round(f float64, precision int) float64 {
	pow := math.Pow10(precision)
	return float64(int64(f*pow)) / pow
}

// RegQuery issues a reg query command to dump registry
func RegQuery(key, value string) (string, error) {
	c := exec.Command("reg", "query", key, "/v", value)
	out, err := c.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Utf16ToUtf8 converts a utf16 encoded byte slice to utf8 byte slice
// it returns error if there is any decoding / encoding issue
// Inspired by: https://gist.github.com/bradleypeabody/185b1d7ed6c0c2ab6cec#file-gistfile1-go
func Utf16ToUtf8(b []byte) ([]byte, error) {

	u16s := make([]uint16, 1)
	ret := &bytes.Buffer{}
	b8buf := make([]byte, 4)

	if len(b)%2 != 0 {
		return nil, fmt.Errorf("expecting even data length")
	}

	for i := 0; i < len(b); i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)[0]
		// skip BOM
		if i == 0 && r == '\ufeff' {
			continue
		}
		if r == utf8.RuneError {
			return nil, fmt.Errorf("invalid UTF-16 code point")
		}
		if !utf8.ValidRune(r) {
			return nil, fmt.Errorf("cannot UTF-16 code point to UTF-8")
		}
		n := utf8.EncodeRune(b8buf, r)
		ret.Write(b8buf[:n])
	}

	return ret.Bytes(), nil
}
