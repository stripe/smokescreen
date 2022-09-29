package conntrack

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
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

	return NewTracker(idle, metrics.NewNoOpMetricsClient(), logrus.New(), sd, nil)
}

// TestConnSuccessRateTracker tests that a ConnTracker with a ConnSuccessRateTracker correctly
// records connection attempts, calculates a success rate, and expires stored attempts.
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
		{"no-records", []record{}, 2 * time.Second, 100.0, 0},
		// If we wait beyond the calculation window, we should have no records and return the default 100% rate
		{"expire-records", []record{{"foo.com", true}, {"bar.com", false}}, 3 * time.Second, 100.0, 0},
		// Only the most recent record for a host is used in the computation
		{"dedup-hosts", []record{{"foo.com", false}, {"bar.com", false}, {"foo.com", true}}, 1 * time.Second, 50.0, 2},
		// Our normalization scheme should resolve all of these to "foo.com"
		{"hostnames-normalized", []record{{"one.foo.com:443", false}, {"two.foo.com:80", false}, {"three.bar.foo.com", true}}, 1 * time.Second, 100.0, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)

			sd := atomic.Value{}
			sd.Store(false)
			mockMetricsClient := metrics.NewMockMetricsClient()
			tracker := NewTracker(
				time.Second,
				metrics.NewNoOpMetricsClient(), // We aren't testing metrics for the Tracker here, only for the embedded ConnSuccessRateTracker
				logrus.New(),
				sd,
				StartNewConnSuccessRateTracker(500*time.Millisecond, 2*time.Second, 10*time.Second, mockMetricsClient))

			for _, record := range tc.additions {
				tracker.RecordAttempt(record.host, record.success)
			}

			time.Sleep(tc.waitTime)

			stats := tracker.ReportConnectionSuccessRate()
			assert.InDelta(tc.expectedRate, stats.ConnSuccessRate, 0.01)
			assert.Equal(tc.totalConns, stats.TotalConns)

			v, err := mockMetricsClient.GetValues("cn.atpt.distinct_domains_success_rate", map[string]string{})
			assert.NoError(err)
			assert.Equal(tc.expectedRate, v[len(v)-1])

			v, err = mockMetricsClient.GetValues("cn.atpt.distinct_domains", map[string]string{})
			assert.NoError(err)
			assert.Equal(tc.totalConns, int(v[len(v)-1]))

		})
	}
}

func TestNoConnSuccessRateTracker(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTestTracker(time.Second)

	assert.NotPanics(func() { tracker.RecordAttempt("foo.com", true) })
	stats := tracker.ReportConnectionSuccessRate()
	assert.Nil(stats)

}

func TestNormalizeDomainName(t *testing.T) {

	var testCases = []struct {
		domain     string
		normalized string
	}{
		{"34wfasdaskjgsf.hosting.company.com:443", "company.com"},
		{"foo.com", "foo.com"},
		{"bbc.co.uk:12345", "bbc.co.uk"},
		{"ab.cd.ef.co:000", "ef.co"},
		{"172.168.0.1:555", "172.168.0.1"},
		{"[2001:db8::1]:80", "2001:db8::1"},
	}

	for _, tc := range testCases {
		t.Run("normalize_test_"+tc.domain, func(t *testing.T) {
			assert.Equal(t, tc.normalized, normalizeDomainName(tc.domain))
		})
	}
}
