package api

import (
	"sync"
	"time"

	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/hids/sysinfo"
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
	Command        *Command            `json:"command,omitempty"`
	Score          float64             `json:"score"`
	Status         string              `json:"status"`
	SystemInfo     *sysinfo.SystemInfo `json:"system-info,omitempty"`
	LastDetection  time.Time           `json:"last-detection"`
	LastConnection time.Time           `json:"last-connection"`
}

// NewEndpoint returns a new Endpoint structure
func NewEndpoint(uuid, key string) *Endpoint {
	return &Endpoint{Uuid: uuid, Key: key}
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

// Endpoints structure used to manage endpoints
// This struct looks over complicated for what it
// does but it is because it was more complex before
// and got simplified (too lazy to change it...)
type Endpoints struct {
	sync.RWMutex
	endpoints []*Endpoint
	mapUUID   map[string]int
}

// NewEndpoints creates a new Endpoints structure
func NewEndpoints() Endpoints {
	return Endpoints{
		endpoints: make([]*Endpoint, 0),
		mapUUID:   make(map[string]int),
	}
}

// Add adds an Endpoint to the Endpoints
func (es *Endpoints) Add(e *Endpoint) {
	es.Lock()
	defer es.Unlock()
	es.endpoints = append(es.endpoints, e)
	es.mapUUID[e.Uuid] = len(es.endpoints) - 1
}

// DelByUUID deletes an Endpoint by its UUID
func (es *Endpoints) DelByUUID(uuid string) {
	es.Lock()
	defer es.Unlock()
	if i, ok := es.mapUUID[uuid]; ok {
		delete(es.mapUUID, uuid)

		switch {
		case i == 0:
			if len(es.endpoints) == 1 {
				es.endpoints = make([]*Endpoint, 0)
			} else {
				es.endpoints = es.endpoints[i+1:]
			}
		case i == len(es.endpoints)-1:
			es.endpoints = es.endpoints[:i]
		default:
			es.endpoints = append(es.endpoints[:i], es.endpoints[i+1:]...)
		}
	}
}

func (es *Endpoints) HasByUUID(uuid string) bool {
	es.RLock()
	defer es.RUnlock()
	_, ok := es.mapUUID[uuid]
	return ok
}

// GetByUUID returns a reference to the copy of an Endpoint by its UUID
func (es *Endpoints) GetByUUID(uuid string) (*Endpoint, bool) {
	es.RLock()
	defer es.RUnlock()
	if i, ok := es.mapUUID[uuid]; ok {
		return es.endpoints[i].Copy(), true
	}
	return nil, false
}

// GetMutByUUID returns reference to an Endpoint
func (es *Endpoints) GetMutByUUID(uuid string) (*Endpoint, bool) {
	es.RLock()
	defer es.RUnlock()
	if i, ok := es.mapUUID[uuid]; ok {
		return es.endpoints[i], true
	}
	return nil, false
}

// Len returns the number of endpoints
func (es *Endpoints) Len() int {
	es.RLock()
	defer es.RUnlock()
	return len(es.endpoints)
}

// Endpoints returns a list of references to copies of the endpoints
func (es *Endpoints) Endpoints() []*Endpoint {
	es.RLock()
	defer es.RUnlock()
	endpts := make([]*Endpoint, 0, len(es.endpoints))
	for _, e := range es.endpoints {
		endpts = append(endpts, e.Copy())
	}
	return endpts
}

// MutEndpoints returns a list of references of the endpoints
func (es *Endpoints) MutEndpoints() []*Endpoint {
	es.RLock()
	defer es.RUnlock()
	endpts := make([]*Endpoint, len(es.endpoints))
	copy(endpts, es.endpoints)
	return endpts
}
