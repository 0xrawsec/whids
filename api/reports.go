package api

import (
	"time"

	"github.com/0xrawsec/gene/v2/reducer"
	"github.com/0xrawsec/sod"
)

type ArchivedReport struct {
	sod.Item
	reducer.ReducedStats
	ArchivedTimestamp time.Time `json:"archived-time"`
}
