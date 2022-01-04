package api

import (
	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/sod"
)

type EdrRule struct {
	sod.Item
	engine.Rule
}
