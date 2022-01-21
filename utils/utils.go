package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/utils/powershell"
)

var (
	RegexUuid = regexp.MustCompile(`^(?i:[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})$`)
)

func IsValidUUID(uuid string) bool {
	return RegexUuid.MatchString(uuid)
}

// EnableDNSLogs through wevutil command line
func EnableDNSLogs() error {
	cmd := exec.Command("wevtutil.exe", "sl", "Microsoft-Windows-DNS-Client/Operational", "/e:true")
	return cmd.Run()
}

// FlushDNSCache executes windows command to flush the DNS cache
func FlushDNSCache() error {
	cmd := exec.Command("ipconfig.exe", "/flushdns")
	return cmd.Run()
}

// PrettyJson returns a JSON pretty string out of i
func PrettyJson(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func Json(i interface{}) []byte {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	return b
}

// JsonString returns a Json string out of i
func JsonString(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	return string(b)
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
func HashEventBytes(b []byte) string {
	return data.Sha1(bytes.Trim(b, " \n\r\t"))
}

func HashStruct(i interface{}) (h string, err error) {
	var b []byte

	if b, err = json.Marshal(i); err != nil {
		return
	}

	return data.Sha1(bytes.Trim(b, " \n\r\t")), nil
}

func GetCurFuncName() string {
	if pc, _, _, ok := runtime.Caller(1); ok {
		split := strings.Split(runtime.FuncForPC(pc).Name(), "/")
		return split[len(split)-1]
	}
	return "unk.UnknownFunc"
}

/////////////////////////////// Windows Logger ////////////////////////////////

const (
	newEventLog    = `New-EventLog -Source "%s" -LogName "%s"`
	writeEventLog  = `Write-EventLog -LogName "%s" -Source "%s" -EventID %d -EntryType %s -Message '%s'`
	removeEventLog = `Remove-EventLog -Source "%s"`
)

var (
	entryTypesAllowed = datastructs.NewInitSyncedSet("Error", "Information", "FailureAudit", "SuccessAudit", "Warning")
)

// WindowsLogger structure definition
type WindowsLogger struct {
	p       *powershell.Powershell
	Channel string
	Source  string
}

// NewWindowsLogger creates a new WindowsLogger structure
func NewWindowsLogger(channel, source string) (wl *WindowsLogger, err error) {
	wl = &WindowsLogger{Channel: channel, Source: source}
	wl.p, err = powershell.NewShell()
	if err != nil {
		return
	}
	command := fmt.Sprintf(newEventLog, wl.Source, wl.Channel)
	log.Debug(command)
	wl.p.ExecuteString(command)
	return
}

// Log logs a message through powershell Write-EventLog
func (w *WindowsLogger) Log(eventid int, entrytype, message string) {
	if !entryTypesAllowed.Contains(entrytype) {
		entrytype = "Information"
	}
	message = strings.Replace(message, "\n", "\\n", -1)
	command := fmt.Sprintf(writeEventLog, w.Channel, w.Source, eventid, entrytype, message)
	log.Debug(command)
	w.p.ExecuteString(command)
}

// Close closes the logger in a clean fashion
func (w *WindowsLogger) Close() error {
	command := fmt.Sprintf(removeEventLog, w.Source)
	w.p.ExecuteString(command)
	log.Debug(command)
	time.Sleep(1 * time.Second)
	return w.p.Kill()
}

// Round float f to precision
func Round(f float64, precision int) float64 {
	pow := math.Pow10(precision)
	return float64(int64(f*pow)) / pow
}

// SvcFromPid returns the list of services hosted by a given PID
// interesting to know what service is hosted by svchost
func SvcFromPid(pid int32) string {
	c := exec.Command("tasklist", "/SVC", "/FO", "CSV", "/NH", "/FI", fmt.Sprintf("PID eq %d", pid))

	out, err := c.Output()
	if err != nil {
		log.Errorf("Failed to run tasklist: %s", err)
		return "ERROR"
	}

	r := csv.NewReader(bytes.NewBuffer(out))
	rec, err := r.Read()
	if err != nil {
		log.Errorf("Failed to read tasklist output: %s", err)
		return "ERROR"
	}

	// Expect three fields
	if len(rec) == 3 {
		return rec[2]
	}
	log.Errorf("Unexpected tasklist output: %s", out)
	return "ERROR"
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
		return nil, fmt.Errorf("Expecting even data length")
	}

	for i := 0; i < len(b); i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)[0]
		// skip BOM
		if i == 0 && r == '\ufeff' {
			continue
		}
		if r == utf8.RuneError {
			return nil, fmt.Errorf("Invalid UTF-16 code point")
		}
		if !utf8.ValidRune(r) {
			return nil, fmt.Errorf("Cannot UTF-16 code point to UTF-8")
		}
		n := utf8.EncodeRune(b8buf, r)
		ret.Write(b8buf[:n])
	}

	return ret.Bytes(), nil
}

type ByteSlice []byte

func (b ByteSlice) Len() int {
	return len(b)
}

func (b ByteSlice) Swap(i, j int) {
	s := b[i]
	b[i] = b[j]
	b[j] = s
}

func (b ByteSlice) Less(i, j int) bool {
	return b[i] < b[j]
}
