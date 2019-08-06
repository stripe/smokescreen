package conntrack

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/sirupsen/logrus"
)

type Tracker struct {
	*sync.Map
	Wg            *sync.WaitGroup
	IdleThreshold time.Duration // A connection is idle if it has been inactive (no bytes transferred) for this many seconds.
	Log           *logrus.Logger
	statsc        *statsd.Client
}

func NewTracker(idle time.Duration, statsc *statsd.Client, logger *logrus.Logger) *Tracker {
	return &Tracker{
		Map:           &sync.Map{},
		Wg:            &sync.WaitGroup{},
		IdleThreshold: idle,
		Log:           logger,
		statsc:        statsc,
	}
}
