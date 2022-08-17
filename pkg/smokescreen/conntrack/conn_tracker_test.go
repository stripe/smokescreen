package conntrack

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var testLogger = logrus.New()

// TestConnTrackerDelete is a sanity check to ensure we aren't leaking
// connection references in the tracker's sync.Map
func TestConnTrackerDelete(t *testing.T) {
	tr := NewTestTracker(time.Second * 1)

	ic := tr.NewInstrumentedConn(&net.UnixConn{}, logrus.NewEntry(testLogger), "testDeleteConn", "localhost", "http")
	ic.Close()

	tr.Range(func(k, v interface{}) bool {
		t.Fatal("conn map should be empty")
		return false
	})
}

// TestConnTrackerMaybeIdleIn tests that our `IdleIn` calculations are correct
func TestConnTrackerMaybeIdleIn(t *testing.T) {
	assert := assert.New(t)

	tr := NewTestTracker(time.Nanosecond)
	ic := tr.NewInstrumentedConn(&net.UnixConn{}, logrus.NewEntry(testLogger), "testMaybeIdle", "localhost", "http")

	time.Sleep(time.Millisecond)

	// All connections should be idle
	assert.Zero(tr.MaybeIdleIn(time.Nanosecond))

	ic.Write([]byte("egress"))

	idleIn := tr.MaybeIdleIn(time.Second).Round(time.Second)
	assert.Equal(time.Second, idleIn)
}

func NewTestTracker(idle time.Duration) *Tracker {
	sd := atomic.Value{}
	sd.Store(false)

	return NewTracker(idle, &statsd.NoOpClient{}, logrus.New(), sd, nil)
}

func TestConnSuccessRateTracker(t *testing.T) {
	type record struct {
		host    string
		success bool
	}

	var testCases = []struct {
		name         string
		additions    []record
		waitTime     time.Duration
		expectedRate float64
		totalConns   int
	}{
		{"fifty-percent-success", []record{{"foo.com", true}, {"bar.com", false}}, 1 * time.Second, 50.0, 2},
		{"no-records", []record{}, 0 * time.Second, 100.0, 0},
		// If we wait beyond the calculation window, we should have no records and return the default 100% rate
		{"expire-records", []record{{"foo.com", true}, {"bar.com", false}}, 3 * time.Second, 100.0, 0},
		// Only the most recent record for a host is used in the computation
		{"dedup-hosts", []record{{"foo.com", false}, {"bar.com", false}, {"foo.com", true}}, 1 * time.Second, 50.0, 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)

			sd := atomic.Value{}
			sd.Store(false)
			tracker := NewTracker(time.Second, &statsd.NoOpClient{}, logrus.New(), sd, StartNewConnSuccessRateTracker(500*time.Millisecond, 2*time.Second))

			for _, record := range tc.additions {
				tracker.RecordAttempt(record.host, record.success)
			}

			time.Sleep(tc.waitTime)

			stats, _ := tracker.ReportConnectionSuccessRate()
			assert.Equal(tc.expectedRate, stats.ConnSuccessRate)
			assert.Equal(tc.totalConns, stats.TotalConns)
		})
	}
}

func TestNoConnSuccessRateTracker(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTestTracker(time.Second)

	assert.Error(tracker.RecordAttempt("foo.com", true))
	_, err := tracker.ReportConnectionSuccessRate()
	assert.Error(err)

}
