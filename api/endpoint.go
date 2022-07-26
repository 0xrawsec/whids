package api

import (
	"fmt"
	"time"

	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/agent/sysinfo"
)

// Endpoint structure used to track and interact with endpoints
type Endpoint struct {
	sod.Item
	Uuid           string              `json:"uuid" sod:"unique"`
	Hostname       string              `json:"hostname"`
	IP             string              `json:"ip"`
	Group          string              `json:"group"`
	Criticality    int                 `json:"criticality"`
	Key            string              `json:"key,omitempty"`
	Command        *EndpointCommand    `json:"command,omitempty"`
	Score          float64             `json:"score"`
	Status         string              `json:"status"`
	SystemInfo     *sysinfo.SystemInfo `json:"system-info,omitempty"`
	Config         *config.Agent
	LastEvent      time.Time `json:"last-event"`
	LastDetection  time.Time `json:"last-detection"`
	LastConnection time.Time `json:"last-connection"`
}

// NewEndpoint returns a new Endpoint structure
func NewEndpoint(uuid, key string) *Endpoint {
	e := &Endpoint{Uuid: uuid, Key: key}
	e.Initialize(e.Uuid)
	return e
}

// Validate overwrite sod.Item function
func (e *Endpoint) Validate() error {
	if e.Criticality < 0 || e.Criticality > 10 {
		return fmt.Errorf("criticality field must be in [0;10]")
	}
	return nil
}

// Copy returns a pointer to a new copy of the Endpoint
func (e *Endpoint) Copy() *Endpoint {
	new := *e
	return &new
}

// UpdateLastConnection updates the LastConnection member of Endpoint structure
func (e *Endpoint) UpdateLastConnection() {
	e.LastConnection = time.Now().UTC()
}
