package conntrack

import (
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

	SuccessRateTracker *ConnSuccessRateTracker

	// A connection is idle if it has been inactive (no bytes in/out) for this
	// many seconds.
	IdleTimeout time.Duration
}

// ConnSuccessRateTracker tracks statistics about the overall success rate
// of connection attempts over some time interval (which is set in StartNewConnSuccessRateTracker()).
//
// It tracks only the *most recently seen* connection to an individual destination host within the configured
// time interval, to prevent a single destination host from having an outsized
// impact on statistics.
type ConnSuccessRateTracker struct {
	ConnAttempts *cache.Cache
	// The success rate of connection attempts, calculated over
	// ConnAttempts over the interval configured in StartNewConnSuccessRateTracker()
	ConnSuccessRateStats atomic.Value
}

// ConnSuccessRateStats represents a timestamped output of computations performed over
// connection attempts.
type ConnSuccessRateStats struct {
	CalculatedAt    time.Time
	ConnSuccessRate float64
	TotalConns      int
}

// StartNewConnSuccessRateTracker creates a new ConnSuccessRateTracker with a specific calculation interval at which
// ConnSuccessRateStats will be recomputed, and a time window to calculate those statistics over.
func StartNewConnSuccessRateTracker(calculationInterval time.Duration, calculationWindow time.Duration) *ConnSuccessRateTracker {
	newSuccessTracker := &ConnSuccessRateTracker{
		ConnAttempts: cache.New(calculationWindow, time.Second*10),
	}
	newSuccessTracker.ConnSuccessRateStats.Store(ConnSuccessRateStats{CalculatedAt: time.Now(), ConnSuccessRate: 100, TotalConns: 0})

	go func() {
		for {
			var total, succeeded int
			for _, success := range newSuccessTracker.ConnAttempts.Items() {
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
			newSuccessTracker.ConnSuccessRateStats.Store(ConnSuccessRateStats{CalculatedAt: time.Now(), ConnSuccessRate: successRate, TotalConns: total})

			time.Sleep(calculationInterval)
		}
	}()

	return newSuccessTracker
}

func NewTracker(idle time.Duration, statsc statsd.ClientInterface, logger *logrus.Logger, sd atomic.Value, successRateTracker *ConnSuccessRateTracker) *Tracker {
	return &Tracker{
		Map:                &sync.Map{},
		ShuttingDown:       sd,
		Wg:                 &sync.WaitGroup{},
		IdleTimeout:        idle,
		statsc:             statsc,
		SuccessRateTracker: successRateTracker,
	}
}

// RecordAttempt stores the result of the most recent connection attempt for a destination.
func (tr *Tracker) RecordAttempt(dest string, success bool) {
	if tr.SuccessRateTracker == nil {
		return
	}
	tr.SuccessRateTracker.ConnAttempts.Set(dest, success, cache.DefaultExpiration)
}

func (tr *Tracker) ReportConnectionSuccessRate() ConnSuccessRateStats {
	if tr.SuccessRateTracker != nil {
		return tr.SuccessRateTracker.ConnSuccessRateStats.Load().(ConnSuccessRateStats)
	}
	return ConnSuccessRateStats{}
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
