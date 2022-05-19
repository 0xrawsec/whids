package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/utils"
)

const (
	ToolSysmon   = "sysmon"
	ToolOSQueryi = "osqueryi"
)

func WithExecExt(name string) string {
	return fmt.Sprintf("%s%s", name, los.ExecExt)
}

type Metadata struct {
	Md5    string `sod:"lower,index" json:"md5"`
	Sha1   string `sod:"lower,index" json:"sha1"`
	Sha256 string `sod:"lower,index" json:"sha256"`
	Sha512 string `sod:"lower,index" json:"sha512"`
}

type Tool struct {
	sod.Item
	Uuid     string   `sod:"index,unique" json:"uuid"`
	OS       string   `sod:"index" json:"os"`
	Name     string   `sod:"index" json:"name"`
	Alias    string   `json:"alias"`
	Metadata Metadata `json:"metadata"`
	Binary   []byte   `json:"binary,omitempty"`
}

func New(os, name, alias string, binary []byte) (t *Tool) {

	if alias == "" {
		alias, _, _ = strings.Cut(name, ".")
	}

	t = &Tool{
		OS:    os,
		Name:  name,
		Alias: alias,
	}

	// using tool's uuid for object storage
	t.Uuid = utils.UnsafeUUIDGen().String()
	t.Initialize(t.Uuid)

	t.Update(binary)

	return
}

func (t *Tool) Update(binary []byte) {
	t.Binary = binary
	t.Metadata = Metadata{
		Md5:    data.Md5(binary),
		Sha1:   data.Sha1(binary),
		Sha256: data.Sha256(binary),
		Sha512: data.Sha512(binary),
	}
}

func (t *Tool) Filepath(dir string) string {
	base := fmt.Sprintf("%s%s", t.Name, los.ExecExt)
	return filepath.Join(dir, base)
}

func (t *Tool) Dump(dir string) error {
	if err := utils.HidsMkdirAll(dir); err != nil {
		return err
	}
	return utils.HidsWriteData(t.Filepath(dir), t.Binary)
}

func (t *Tool) Remove(dir string) error {
	return os.Remove(t.Filepath(dir))
}

// Validate function triggered by database insertion
// Structure will not be inserted if any error is returned by
// this function
func (t *Tool) Validate() error {

	if strings.Contains(t.Name, los.WinPathSep) || strings.Contains(t.Name, los.NixPathSep) {
		return fmt.Errorf("tool name must not contain any path separator")
	}

	if !los.IsKnownOS(t.OS) {
		return fmt.Errorf("unknown OS %s", t.OS)
	}

	return nil
}
