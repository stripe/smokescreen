package conntrack

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	cache "github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type Tracker struct {
	*sync.Map
	ShuttingDown atomic.Value
	Wg           *sync.WaitGroup
	statsc       statsd.ClientInterface

	CnAttempts *cache.Cache

	// A connection is idle if it has been inactive (no bytes in/out) for this
	// many seconds.
	IdleTimeout time.Duration
}

func NewTracker(idle time.Duration, statsc statsd.ClientInterface, logger *logrus.Logger, sd atomic.Value) *Tracker {
	return &Tracker{
		Map:          &sync.Map{},
		ShuttingDown: sd,
		Wg:           &sync.WaitGroup{},
		IdleTimeout:  idle,
		statsc:       statsc,
		CnAttempts:   cache.New(time.Second*30, time.Second*30),
	}
}

// RecordAttempt stores the result of the most recent connection attempt for a destination.
func (tr *Tracker) RecordAttempt(dest string, success bool) {
	tr.CnAttempts.Set(dest, success, cache.DefaultExpiration)
}

func (tr *Tracker) ReportConnectionSuccessRate() string {
	var total, succeeded int
	for _, success := range tr.CnAttempts.Items() {
		total++
		if success.Object.(bool) {
			succeeded++
		}
	}
	var successRate float64
	// Avoid divide by zero errors
	if total == 0 {
		successRate = float64(100)
	} else {
		successRate = (float64(succeeded) / float64(total)) * 100
	}
	jsondata := map[string]interface{}{
		"destinations_attempted":  total,
		"destinations_succeeded":  succeeded,
		"connection_success_rate": successRate,
	}

	data, _ := json.Marshal(jsondata)

	return string(data)

}

// MaybeIdleIn returns the longest amount of time it will take for all tracked
// connections to become idle based on the configured IdleTimeout.
//
// A duration of 0 indicates all connections are idle.
func (tr *Tracker) MaybeIdleIn(d time.Duration) time.Duration {
	longest := 0 * time.Nanosecond
	tr.Range(func(k, v interface{}) bool {
		c := k.(*InstrumentedConn)

		lastActivity := time.Unix(0, atomic.LoadInt64(c.LastActivity))
		idleAt := lastActivity.Add(d)
		idleIn := time.Until(idleAt)

		if idleIn > longest {
			longest = idleIn
		}
		return true
	})
	return longest
}
