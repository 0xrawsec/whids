//go:build windows
// +build windows

package sysmon

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/file"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/whids/utils"
)

const (
	servicesPath = `HKLM\SYSTEM\CurrentControlSet\Services`
	driverPath   = `C:\Windows`
)

var (
	versionRe = regexp.MustCompile(
		`(?s:System\sMonitor\s(?P<version>v\d+\.\d+)\s-[.\s].*` +
			`<manifest schemaversion="(?P<schemaversion>\d+\.\d+)" binaryversion="(?P<binaryversion>\d+\.\d+)">)`,
	)
)

func findMatchingSysmonServiceKeys() (keys []string) {
	keys = make([]string, 0)

	if skeys, err := advapi32.RegEnumKeys(servicesPath); err != nil {
		return
	} else {
		for _, skey := range skeys {
			fullSubKey := utils.RegJoin(servicesPath, skey)
			descValue := utils.RegJoin(fullSubKey, "Description")
			if desc := utils.RegValueToString(descValue); desc != "" {
				if strings.EqualFold(desc, "System Monitor service") {
					keys = append(keys, skey)
				}
			}
		}
	}
	return
}

func NewSysmonConfig() (s *Sysmon) {
	var sysmonRegPath string

	s = &Sysmon{}

	// validate that we find only one entry in registry
	if keys := findMatchingSysmonServiceKeys(); len(keys) != 1 {
		s.Err = fmt.Errorf("more than one key looking like Sysmon: %v", keys)
		return
	} else {
		s.Service.Name = keys[0]
	}

	sysmonRegPath = utils.RegJoin(servicesPath, s.Service.Name)
	s.Service.Image = utils.RegValueToString(sysmonRegPath, "ImagePath")
	s.Service.Sha256, _ = file.Sha256(s.Service.Image)

	s.Driver.Name = s.DriverName()
	s.Driver.Image = filepath.Join(driverPath, utils.RegValueToString(s.DriverRegistry(), "ImagePath"))
	s.Driver.Sha256, _ = file.Sha256(s.Driver.Image)

	s.Config.Hash = s.ConfigHash()

	// parse schema and populate version information
	s.parseSchema()

	return
}

func (s *Sysmon) ServiceRegistry() string {
	return utils.RegJoin(servicesPath, s.Service.Name)
}

func (s *Sysmon) ServiceParametersRegistry() string {
	return utils.RegJoin(servicesPath, s.Service.Name, "Parameters")
}

func (s *Sysmon) DriverName() string {
	if s.Driver.Name != "" {
		return s.Driver.Name
	}
	return utils.RegValueToString(s.ServiceParametersRegistry(), "DriverName")
}

func (s *Sysmon) DriverRegistry() string {
	return utils.RegJoin(servicesPath, s.DriverName())
}

func (s *Sysmon) DriverParametersRegistry() string {
	return utils.RegJoin(s.DriverRegistry(), "Parameters")
}

func (s *Sysmon) ConfigHash() string {
	if s.Config.Hash != "" {
		return s.Config.Hash
	}
	hash := utils.RegValueToString(s.DriverParametersRegistry(), "ConfigHash")
	if i := strings.Index(hash, "="); i > -1 && i+1 < len(hash) {
		hash = strings.ToLower(hash[i+1:])
	}
	return hash
}

func (s *Sysmon) parseSchema() {
	sh := submatch.NewHelper(versionRe)

	if s.Service.Image != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		if out, err := exec.CommandContext(
			ctx,
			s.Service.Image,
			"-s",
		).CombinedOutput(); err == nil {
			if len(out) >= 2 {
				// check UTF16 BOM
				if out[1] == '\xfe' && out[0] == '\xff' {
					out = []byte(win32.UTF16BytesToString(out))
				}
			}
			sh.Prepare(out)
			if v, err := sh.GetBytes("version"); err == nil {
				s.Version = string(v)
			}
			if sv, err := sh.GetBytes("schemaversion"); err == nil {
				s.Config.Version.Schema = string(sv)
			}
			if bv, err := sh.GetBytes("binaryversion"); err == nil {
				s.Config.Version.Binary = string(bv)
			}
		} else {
			s.Err = fmt.Errorf("failed to run sysmon command: %s", err)
		}
		cancel()
	}
}
