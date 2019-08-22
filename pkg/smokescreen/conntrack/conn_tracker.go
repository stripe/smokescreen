package conntrack

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/sirupsen/logrus"
)

type Tracker struct {
	*sync.Map
	ShuttingDown  atomic.Value
	Wg            *sync.WaitGroup
	IdleThreshold time.Duration // A connection is idle if it has been inactive (no bytes in/out) for this many seconds.
	Log           *logrus.Logger
	statsc        *statsd.Client
}

func NewTracker(idle time.Duration, statsc *statsd.Client, logger *logrus.Logger, sd atomic.Value) *Tracker {
	return &Tracker{
		Map:           &sync.Map{},
		ShuttingDown:  sd,
		Wg:            &sync.WaitGroup{},
		IdleThreshold: idle,
		Log:           logger,
		statsc:        statsc,
	}
}
