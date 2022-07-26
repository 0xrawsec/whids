package server

import (
	"github.com/0xrawsec/sod"
)

// AdminAPIUser structure definition
type AdminAPIUser struct {
	sod.Item
	Uuid        string `json:"uuid" sod:"unique"`
	Identifier  string `json:"identifier" sod:"unique"`
	Key         string `json:"key,omitempty" sod:"unique"`
	Group       string `json:"group" sod:"index"`
	Description string `json:"description"`
}
