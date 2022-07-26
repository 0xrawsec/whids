package config

import (
	"time"
)

// ForwarderLogging structure to encode Logging configuration of the forwarder
type ForwarderLogging struct {
	Dir              string        `toml:"dir" comment:"Directory used to store logs"`
	RotationInterval time.Duration `toml:"rotation-interval" comment:"Logfile rotation interval"`
}

// Forwarder config structure definition
type Forwarder struct {
	Local   bool             `toml:"local" comment:"If forwarder is local (this setting equals true)\n neither alerts nor dumps will be forwarded to manager"`
	Client  Client           `toml:"manager" comment:"Configure connection to the manager"`
	Logging ForwarderLogging `toml:"logging" comment:"Forwarder's logging configuration"`
}
