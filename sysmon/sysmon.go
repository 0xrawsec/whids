package sysmon

import "fmt"

var (
	ErrSysmonNotInstalled = fmt.Errorf("sysmon is not installed")
)

type Info struct {
	Version string `json:"version"`

	Service struct {
		Name   string `json:"name"`
		Image  string `json:"image"`
		Sha256 string `json:"sha256"`
	} `json:"service"`
	Driver struct {
		Name   string `json:"name"`
		Image  string `json:"image"`
		Sha256 string `json:"sha256"`
	} `json:"driver"`
	Config struct {
		Version struct {
			Schema string `json:"schema"`
			Binary string `json:"binary"`
		} `json:"version"`
		Hash string `json:"hash"`
	} `json:"config"`
}
