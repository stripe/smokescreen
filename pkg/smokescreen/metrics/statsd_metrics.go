package metrics

import (
	"fmt"
	"github.com/DataDog/datadog-go/statsd"
	"sync/atomic"
	"time"
)

// StatsdMetricsClient is a thin wrapper around statsd.ClientInterface. It is used to allow
// adding arbitrary tags to Smokescreen metrics.
//
// StatsdMetricsClient is not thread safe and should not be used concurrently.
type StatsdMetricsClient struct {
	metricsTags  map[string][]string
	statsdClient statsd.ClientInterface
	started      atomic.Value
}

// NewMetricsClient creates a new StatsdMetricsClient with the provided statsd address and
// namespace.
func NewStatsdMetricsClient(addr, namespace string) (*StatsdMetricsClient, error) {
	c, err := statsd.New(addr)
	if err != nil {
		return nil, err
	}
	c.Namespace = namespace

	// Populate the client's map to hold metric tags
	metricsTags := make(map[string][]string)
	for _, m := range metrics {
		metricsTags[m] = []string{}
	}

	return &StatsdMetricsClient{
		metricsTags:  metricsTags,
		statsdClient: c,
	}, nil
}

// NewNoOpMetricsClient returns a StatsdMetricsClient with a no-op statsd client. This can
// be used when there's no statsd service available to smokescreen.
func NewNoOpMetricsClient() *StatsdMetricsClient {
	// Populate the client's map to hold metric tags
	metricsTags := make(map[string][]string)
	for _, m := range metrics {
		metricsTags[m] = []string{}
	}

	return &StatsdMetricsClient{
		metricsTags:  metricsTags,
		statsdClient: &statsd.NoOpClient{},
	}
}

// AddMetricTags associates the provided tags slice with a given metric. The metric must be present
// in the metrics slice.
//
// Once a metric has tags added via AddMetricTags, those tags will *always* be attached whenever
// that metric is emitted.
// For example, calling `AddMetricTags(foo, [bar])` will cause the `bar` tag to be added to
// *every* metric `foo` that is emitted for the lifetime of the StatsdMetricsClient.
//
// This function is not thread safe, and adding persistent tags should only be done while initializing
// the configuration and prior to running smokescreen.
func (mc *StatsdMetricsClient) AddMetricTags(
	metric string,
	additionalTags map[string]string) error {
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics baseTags after starting smokescreen")
	}
	if baseTags, ok := mc.metricsTags[metric]; ok {
		mc.metricsTags[metric] = append(baseTags, constructTagArray(additionalTags)...)
		return nil
	}
	return fmt.Errorf("unknown metric: %s", metric)
}

// GetMetricTags returns the slice of metrics associated with a given metric.
func (mc *StatsdMetricsClient) GetMetricTags(metric string) []string {
	if tags, ok := mc.metricsTags[metric]; ok {
		return tags
	}
	return nil
}

func (mc *StatsdMetricsClient) Incr(metric string, rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Incr(metric, baseTags, rate)
}

func (mc *StatsdMetricsClient) IncrWithTags(
	metric string,
	additionalTags map[string]string,
	rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	combinedTags := append(constructTagArray(additionalTags), baseTags...)
	return mc.statsdClient.Incr(metric, combinedTags, rate)
}

func (mc *StatsdMetricsClient) Gauge(
	metric string,
	value float64, rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Gauge(metric, value, baseTags, rate)
}

func (mc *StatsdMetricsClient) Histogram(
	metric string,
	value float64,
	rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Histogram(metric, value, baseTags, rate)
}

func (mc *StatsdMetricsClient) HistogramWithTags(
	metric string,
	value float64,
	additionalTags map[string]string,
	rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	combinedTags := append(constructTagArray(additionalTags), baseTags...)
	return mc.statsdClient.Histogram(metric, value, combinedTags, rate)
}

func (mc *StatsdMetricsClient) Timing(metric string, d time.Duration, rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Timing(metric, d, baseTags, rate)
}

func (mc *StatsdMetricsClient) TimingWithTags(
	metric string,
	d time.Duration,
	additionalTags map[string]string,
	rate float64) error {
	baseTags := mc.GetMetricTags(metric)
	combinedTags := append(constructTagArray(additionalTags), baseTags...)
	return mc.statsdClient.Timing(metric, d, combinedTags, rate)
}

func (mc *StatsdMetricsClient) StatsdClient() statsd.ClientInterface {
	return mc.statsdClient
}

func (mc *StatsdMetricsClient) SetStarted() {
	mc.started.Store(true)
}

// StatsdMetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &StatsdMetricsClient{}

func constructTagArray(tags map[string]string) []string {
	var tagArray []string
	for k, v := range tags {
		tagArray = append(tagArray, fmt.Sprintf("%s:%s", k, v))
	}
	return tagArray
}
