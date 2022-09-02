package agent

import (
	"time"

	"github.com/0xrawsec/whids/event"
)

var (
	CriticalityFactor float64 = 2
	MaxIssuesInARow   uint    = 10
)

type EventStats struct {
	start   time.Time
	counter struct {
		channels  map[string]float64
		event     float64
		detection float64
		dynamic   float64
	}
	// for performance issue detection
	row       uint
	notified  time.Time
	threshold float64
	duration  time.Duration
}

func NewEventStats(tresh float64, dur time.Duration) *EventStats {
	now := time.Now()
	return &EventStats{
		start:     now,
		notified:  now,
		threshold: tresh,
		duration:  dur,
	}
}

func (m *EventStats) SinceStart() time.Duration {
	return time.Since(m.start)
}

func (m *EventStats) Start() {
	m.start = time.Now()
	m.notified = time.Now()
}

func (m *EventStats) Threshold() float64 {
	return m.threshold
}

func (m *EventStats) Duration() time.Duration {
	return m.duration
}

func (m *EventStats) Update(e *event.EdrEvent) {
	m.counter.event++
	m.counter.dynamic++
	if e.IsDetection() {
		m.counter.detection++
	}
}

func (m *EventStats) Events() float64 {
	return m.counter.event
}

func (m *EventStats) Detections() float64 {
	return m.counter.detection
}

func (m *EventStats) EPS() float64 {
	delta := time.Since(m.start).Seconds()
	if delta > 0 {
		return m.counter.event / delta
	}
	return 0
}

func (m *EventStats) CriticalEPS() float64 {
	return m.threshold * CriticalityFactor
}

func (m *EventStats) DynEPS() float64 {
	delta := time.Since(m.notified).Seconds()
	if delta > 0 {
		return m.counter.dynamic / delta
	}
	return 0
}

func (m *EventStats) HasPerfIssue() (bool, float64) {
	eps := m.DynEPS()
	if m.DynEPS() >= m.threshold {
		if time.Since(m.notified) > m.duration {
			m.row++
			m.notified = time.Now()
			m.counter.dynamic = 0
			return true, eps
		}
	} else if time.Since(m.notified) > m.duration {
		if m.row > 0 {
			m.row--
		}
		m.notified = time.Now()
		m.counter.dynamic = 0
	}

	return false, eps
}

func (m *EventStats) HasCriticalPerfIssue() bool {
	return m.row > uint(MaxIssuesInARow)
}
