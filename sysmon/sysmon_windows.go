//go:build windows
// +build windows

package sysmon

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/file"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/whids/utils"
	"github.com/0xrawsec/whids/utils/command"
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

func Install(image string) (err error) {

	// we first uninstall existing installation
	if err = Uninstall(); err != nil {
		return
	}

	// we run install  
	c := command.CommandTimeout(30, image, "-accepteula", "-i")
	defer c.Terminate()
	if err = c.Run(); err != nil {
		return fmt.Errorf("failed to install sysmon: %w", err)
	}

	return
}

func Configure(config string) (err error) {
	i := NewSysmonInfo()

	image := i.Service.Image

	if fsutil.IsFile(image) {
		c := command.CommandTimeout(5, image, "-c", config)
		defer c.Terminate()
		return c.Run()
	}

	return ErrSysmonNotInstalled
}

func Uninstall() (err error) {
	i := NewSysmonInfo()

	image := i.Service.Image

	//means sysmon is already installed
	if fsutil.IsFile(image) {
		// we uninstall it
		c := command.CommandTimeout(60, image, "-u")
		defer c.Terminate()
		if err = c.Run(); err != nil {
			return fmt.Errorf("failed to uninstall sysmon: %w", err)
		}
	}

	return
}

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

func NewSysmonInfo() (i *Info) {
	var sysmonRegPath string

	i = &Info{}

	// validate that we find only one entry in registry
	if keys := findMatchingSysmonServiceKeys(); len(keys) != 1 {
		i.Err = fmt.Errorf("more than one key looking like Sysmon: %v", keys)
		return
	} else {
		i.Service.Name = keys[0]
	}

	sysmonRegPath = utils.RegJoin(servicesPath, i.Service.Name)
	i.Service.Image = utils.RegValueToString(sysmonRegPath, "ImagePath")
	i.Service.Sha256, _ = file.Sha256(i.Service.Image)

	i.Driver.Name = i.DriverName()
	i.Driver.Image = filepath.Join(driverPath, utils.RegValueToString(i.DriverRegistry(), "ImagePath"))
	i.Driver.Sha256, _ = file.Sha256(i.Driver.Image)

	i.Config.Hash = i.ConfigHash()

	// parse schema and populate version information
	i.parseSchema()

	return
}

func (i *Info) ServiceRegistry() string {
	return utils.RegJoin(servicesPath, i.Service.Name)
}

func (i *Info) ServiceParametersRegistry() string {
	return utils.RegJoin(servicesPath, i.Service.Name, "Parameters")
}

func (i *Info) DriverName() string {
	if i.Driver.Name != "" {
		return i.Driver.Name
	}
	return utils.RegValueToString(i.ServiceParametersRegistry(), "DriverName")
}

func (i *Info) DriverRegistry() string {
	return utils.RegJoin(servicesPath, i.DriverName())
}

func (i *Info) DriverParametersRegistry() string {
	return utils.RegJoin(i.DriverRegistry(), "Parameters")
}

func (i *Info) ConfigHash() string {
	if i.Config.Hash != "" {
		return i.Config.Hash
	}
	hash := utils.RegValueToString(i.DriverParametersRegistry(), "ConfigHash")
	if i := strings.Index(hash, "="); i > -1 && i+1 < len(hash) {
		hash = strings.ToLower(hash[i+1:])
	}
	return hash
}

func (i *Info) parseSchema() {
	sh := submatch.NewHelper(versionRe)

	if fsutil.IsFile(i.Service.Image) {

		c := command.CommandTimeout(
			time.Second*2,
			i.Service.Image,
			"-s",
		)
		defer c.Terminate()

		if out, err := c.CombinedOutput(); err == nil {
			if len(out) >= 2 {
				// check UTF16 BOM
				if out[1] == '\xfe' && out[0] == '\xff' {
					out = []byte(win32.UTF16BytesToString(out))
				}
			}
			sh.Prepare(out)
			if v, err := sh.GetBytes("version"); err == nil {
				i.Version = string(v)
			}
			if sv, err := sh.GetBytes("schemaversion"); err == nil {
				i.Config.Version.Schema = string(sv)
			}
			if bv, err := sh.GetBytes("binaryversion"); err == nil {
				i.Config.Version.Binary = string(bv)
			}
		} else {
			i.Err = fmt.Errorf("failed to run sysmon command: %s", err)
		}
	}
}
