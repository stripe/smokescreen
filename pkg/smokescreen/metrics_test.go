package smokescreen

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMetricsTags(t *testing.T) {
	r := require.New(t)

	t.Run("add custom tags", func(t *testing.T) {
		metric := "acl.allow"
		mc := NewNoOpMetricsClient()

		err := mc.AddMetricTags(metric, []string{"globalize"})
		r.NoError(err)

		tags := mc.GetMetricTags(metric)
		r.Len(tags, 1)
		r.Equal(tags[0], "globalize")

		err = mc.AddMetricTags(metric, []string{"ignore"})
		r.NoError(err)

		tags = mc.GetMetricTags(metric)
		r.Len(tags, 2)
	})

	t.Run("add invalid tags", func(t *testing.T) {
		metric := "acl.does.not.exist"
		mc := NewNoOpMetricsClient()

		err := mc.AddMetricTags(metric, []string{"globalize"})
		r.Error(err)
	})
}

func TestMetricsClient(t *testing.T) {
	r := require.New(t)

	// Passing NewMetricsClient a missing statsd address should always fail
	t.Run("nil statsd addr", func(t *testing.T) {
		mc, err := NewMetricsClient("", "test_namespace")
		r.Error(err)
		r.Nil(mc)
	})

	// MetricsClient is not thread safe. Adding a tag after smokescreen has started
	// should always return an error.
	t.Run("adding metrics after started", func(t *testing.T) {
		mc := NewNoOpMetricsClient()
		mc.started.Store(true)

		err := mc.AddMetricTags("acl.allow", []string{"globalize"})
		r.Error(err)
	})
}

// MockMetricsClient is a MetricsClient that counts metric updates.
type MockMetricsClient struct {
	MetricsClient

	counts map[string]uint64
	mu     sync.Mutex
}

// NewMockMetricsClient returns a new MockMetricsClient that wraps a NoOpMetricsClient
// with counters to track metric updates.
func NewMockMetricsClient() *MockMetricsClient {
	return &MockMetricsClient{
		*NewNoOpMetricsClient(),
		make(map[string]uint64),
		sync.Mutex{},
	}
}

// countOne increments a metric count by 1, starting the count at 1 if the metric has
// not yet been counted. Call with m.mu.Lock held.
func (m *MockMetricsClient) countOne(metric string) {
	if i, ok := m.counts[metric]; ok {
		m.counts[metric] = i + 1
	} else {
		m.counts[metric] = 1
	}
}

func (m *MockMetricsClient) GetCount(metric string, tags ...string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mName := metric
	sort.Strings(tags)
	if len(tags) > 0 {
		mName = fmt.Sprintf("%s %v", mName, tags)
	}
	i, ok := m.counts[mName]
	if !ok {
		keys := make([]string, len(m.counts))
		for k, _ := range m.counts {
			keys = append(keys, k)
		}
		return 0, fmt.Errorf("unknown metric %s (know %s)", mName, strings.Join(keys, ","))
	}

	return i, nil
}

func (m *MockMetricsClient) Incr(metric string, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countOne(metric)

	return m.MetricsClient.Incr(metric, rate)
}

func (m *MockMetricsClient) IncrWithTags(metric string, tags []string, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sort.Strings(tags)
	mName := fmt.Sprintf("%s %v", metric, tags)
	m.countOne(mName)

	return m.MetricsClient.IncrWithTags(metric, tags, rate)
}

func (m *MockMetricsClient) Timing(metric string, d time.Duration, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countOne(metric)

	return m.MetricsClient.Timing(metric, d, rate)
}

func (m *MockMetricsClient) TimingWithTags(metric string, d time.Duration, rate float64, tags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sort.Strings(tags)
	mName := fmt.Sprintf("%s %v", metric, tags)
	m.countOne(mName)

	return m.MetricsClient.TimingWithTags(metric, d, rate, tags)
}

var _ MetricsClientInterface = &MockMetricsClient{}
