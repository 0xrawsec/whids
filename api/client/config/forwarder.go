package config

import (
	"time"
)

// ForwarderLogging structure to encode Logging configuration of the forwarder
type ForwarderLogging struct {
	Dir              string        `json:"dir,omitempty" toml:"dir" comment:"Directory used to store logs"`
	RotationInterval time.Duration `json:"rotation-interval,omitempty" toml:"rotation-interval" comment:"Logfile rotation interval"`
}

// Forwarder config structure definition
type Forwarder struct {
	Local   bool             `json:"local,omitempty" toml:"local" comment:"If forwarder is local (this setting equals true)\n neither alerts nor dumps will be forwarded to manager"`
	Client  Client           `json:"manager,omitempty" toml:"manager" comment:"Configure connection to the manager"`
	Logging ForwarderLogging `json:"logging,omitempty" toml:"logging" comment:"Forwarder's logging configuration"`
}
