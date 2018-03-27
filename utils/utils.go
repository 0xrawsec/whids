package utils

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"utils/powershell"

	"github.com/0xrawsec/golang-utils/datastructs"

	"github.com/0xrawsec/golang-utils/log"
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

// EnableDNSLogs through wevutil command line
func EnableDNSLogs() error {
	cmd := exec.Command("wevtutil.exe", "sl", "Microsoft-Windows-DNS-Client/Operational", "/e:true")
	return cmd.Run()
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
	wl.p.ExecuteString(fmt.Sprintf(newEventLog, wl.Source, wl.Channel))
	return
}

// Log logs a message through powershell Write-EventLog
func (w *WindowsLogger) Log(eventid int, entrytype, message string) {
	if !entryTypesAllowed.Contains(entrytype) {
		entrytype = "Information"
	}
	message = strings.Replace(message, "\n", "\\n", -1)
	w.p.ExecuteString(fmt.Sprintf(writeEventLog, w.Channel, w.Source, eventid, entrytype, message))
}

// Close closes the logger in a clean fashion
func (w *WindowsLogger) Close() error {
	w.p.ExecuteString(fmt.Sprintf(removeEventLog, w.Source))
	time.Sleep(1 * time.Second)
	return w.p.Kill()
}
