package utils

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/whids/utils/powershell"
)

const (
	Mega = 1 << 20
)

// HTTPGet helper function to issue a simple HTTP GET method
func HTTPGet(client *http.Client, url, outPath string) (err error) {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Building new request
	req, err := http.NewRequest("GET", url, new(bytes.Buffer))
	if err != nil {
		return err
	}

	//  Issuing the query
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Bad status code: %d", resp.StatusCode)
	}

	// Dumping the content of the response
	log.Debugf("Dumping the content of the response -> %s", outPath)
	r := -1
	buf := make([]byte, 4096)
	for err == nil && r != 0 {
		r, err = resp.Body.Read(buf)
		out.Write(buf[:r])
	}
	return nil
}

// Unzip helper function to unzip a file to a destination folder
// source code from : https://stackoverflow.com/questions/20357223/easy-way-to-unzip-file-with-golang
func Unzip(zipfile, dest string) (err error) {
	r, err := zip.OpenReader(zipfile)
	if err != nil {
		return err
	}
	defer r.Close()

	// Creating directory
	os.MkdirAll(dest, 0700)

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		path := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			f, err := os.OpenFile(
				path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer f.Close()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// GzipFile compresses a file to gzip and deletes the original file
func GzipFile(path string) (err error) {
	var buf [Mega]byte
	f, err := os.Open(path)
	if err != nil {
		return
	}
	//defer f.Close()
	fname := fmt.Sprintf("%s.gz", path)
	partname := fmt.Sprintf("%s.part", fname)
	of, err := os.Create(partname)
	if err != nil {
		return
	}

	w := gzip.NewWriter(of)
	for n, err := f.Read(buf[:]); err != io.EOF; {
		w.Write(buf[:n])
		n, err = f.Read(buf[:])
	}
	w.Flush()
	// gzip writer
	w.Close()
	// original file
	f.Close()
	// part file
	of.Close()
	log.Infof("Removing original dumpfile: %s", path)
	if err := os.Remove(path); err != nil {
		log.Errorf("Cannot remove original dumpfile: %s", err)
	}
	// rename the file to its final name
	return os.Rename(partname, fname)
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

// ReadFileString reads bytes from a file
func ReadFileString(path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	return string(b), err
}

// PrettyJSON returns a JSON pretty string out of i
func PrettyJSON(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// JSON returns a JSON string out of i
func JSON(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// CountFiles counts files in a directory
func CountFiles(directory string) (cnt int) {
	for wi := range fswalker.Walk(directory) {
		cnt += len(wi.Files)
	}
	return
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

// ArgvFromCommandLine returns an argv slice given a command line
// provided in argument
func ArgvFromCommandLine(cl string) (argv []string, err error) {
	argc := int32(0)
	utf16ClPtr, err := syscall.UTF16PtrFromString(cl)
	if err != nil {
		return
	}
	utf16Argv, err := syscall.CommandLineToArgv(utf16ClPtr, &argc)
	if err != nil {
		return
	}
	argv = make([]string, argc)
	for i, utf16Ptr := range utf16Argv[:argc] {
		argv[i] = syscall.UTF16ToString((*utf16Ptr)[:])
	}
	return
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

// IsPipePath checks whether the argument path is a pipe
func IsPipePath(path string) bool {
	return strings.HasPrefix(path, `\\.\`)
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
