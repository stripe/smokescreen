package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MockMetricsClient is a StatsdMetricsClient that counts metric updates.
type MockMetricsClient struct {
	StatsdMetricsClient

	counts map[string]uint64
	values map[string][]float64
	mu     sync.Mutex
}

// NewMockMetricsClient returns a new MockMetricsClient that wraps a NoOpMetricsClient
// with counters to track metric updates.
func NewMockMetricsClient() *MockMetricsClient {
	return &MockMetricsClient{
		*NewNoOpMetricsClient(),
		make(map[string]uint64),
		make(map[string][]float64),
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

// countOneWithValue increments a metric count by 1 for metrics that emit a value, starting the count at 1 if the metric has
// not yet been counted. Call with m.mu.Lock held.
func (m *MockMetricsClient) countOneWithValue(metric string, value float64) {
	if i, ok := m.counts[metric]; ok {
		m.counts[metric] = i + 1
	} else {
		m.counts[metric] = 1

	}
	m.values[metric] = append(m.values[metric], value)
}

// GetCount returns the number of times metric has been updated since the MockMetricsClient was
// created. To support GetCount being called with or without tags for a given metric, tagged metrics
// are counted twice: once for the untagged metric ("foo") and once for the metric with its tags
// sorted("foo [a b c]").
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

// GetValues returns the values stored for a metric metric has been updated since the MockMetricsClient was
// created. To support GetValues being called with or without tags for a given metric, the values for tagged
// metrics are recorded twice: once for the untagged metric ("foo") and once for the metric with its tags
// sorted("foo [a b c]").
func (m *MockMetricsClient) GetValues(metric string, tags ...string) ([]float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mName := metric
	sort.Strings(tags)
	if len(tags) > 0 {
		mName = fmt.Sprintf("%s %v", mName, tags)
	}
	i, ok := m.values[mName]
	if !ok {
		keys := make([]string, len(m.counts))
		for k, _ := range m.values {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("unknown metric %s (know %s)", mName, strings.Join(keys, ","))
	}

	return i, nil
}

func (m *MockMetricsClient) Incr(metric string, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countOne(metric)

	return m.StatsdMetricsClient.Incr(metric, rate)
}

func (m *MockMetricsClient) IncrWithTags(metric string, tags map[string]string, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Count the metric name without tags
	m.countOne(metric)

	// Count the metric name with its tags sorted
	//sort.Strings(tags)
	mName := fmt.Sprintf("%s %v", metric, tags)
	m.countOne(mName)

	return m.StatsdMetricsClient.IncrWithTags(metric, tags, rate)
}

func (m *MockMetricsClient) Gauge(metric string, value float64, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countOneWithValue(metric, value)

	return m.StatsdMetricsClient.Incr(metric, rate)
}

func (m *MockMetricsClient) Histogram(metric string, value float64, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countOneWithValue(metric, value)

	return m.StatsdMetricsClient.Incr(metric, rate)
}

func (m *MockMetricsClient) HistogramWithTags(metric string, value float64, tags map[string]string, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Count the metric name without tags
	m.countOneWithValue(metric, value)

	// Count the metric name with its tags sorted
	//sort.Strings(tags)
	mName := fmt.Sprintf("%s %v", metric, tags)
	m.countOneWithValue(mName, value)

	return m.StatsdMetricsClient.IncrWithTags(metric, tags, rate)
}

func (m *MockMetricsClient) Timing(metric string, d time.Duration, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countOne(metric)

	return m.StatsdMetricsClient.Timing(metric, d, rate)
}

func (m *MockMetricsClient) TimingWithTags(metric string, d time.Duration, rate float64, tags map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Count the metric name without tags
	m.countOne(metric)

	// Count the metric name with its tags sorted
	//sort.Strings(tags)
	mName := fmt.Sprintf("%s %v", metric, tags)
	m.countOne(mName)

	return m.StatsdMetricsClient.TimingWithTags(metric, d, rate, tags)
}

var _ MetricsClientInterface = &MockMetricsClient{}
