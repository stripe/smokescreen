package metrics

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/DataDog/datadog-go/statsd"
)

// metrics contains all of the metric names contained within the smokescreen package.
// These are used to determine if a given metric name is valid before associating
// a persistent tag with the metric. This list must be updated with new metric names
// if the metric should support persistent tagging.
var metrics = []string{
	// ACL decision statistics
	"acl.allow",
	"acl.decide_error",
	"acl.deny",
	"acl.report",
	"acl.role_not_determined",
	"acl.unknown_error",

	// Connection statistics (cn.atpt == connection attempt)
	"cn.atpt.total",        // Total connection attempts, tagged by success
	"cn.atpt.connect.err",  // Connection failures, tagged by failure type
	"cn.atpt.connect.time", // Connect time in ms, tagged by domain
	// The following are only emitted if Smokescreen is configured to use a ConnSuccessRateTracker.
	"cn.atpt.distinct_domains",              // Number of distinct domains seen by ConnSuccessRateTracker in computation window
	"cn.atpt.distinct_domains_success_rate", // Domain connection success rate computed by ConnSuccessRateTracker

	// DNS resolution statistics
	"resolver.allow.default",
	"resolver.allow.user_configured",
	"resolver.attempts_total",
	"resolver.deny.not_global_unicast",
	"resolver.deny.private_range",
	"resolver.deny.user_configured",
	"resolver.lookup_time", // DNS lookup time in ms, not tagged
	"resolver.errors_total",
}

// MetricsClient is a thin wrapper around statsd.ClientInterface. It is used to allow
// adding arbitrary tags to Smokescreen metrics.
//
// MetricsClient is not thread safe and should not be used concurrently.
type MetricsClient struct {
	metricsTags  map[string][]string
	statsdClient statsd.ClientInterface
	started      atomic.Value
}

type MetricsClientInterface interface {
	AddMetricTags(string, []string) error
	Incr(string, float64) error
	IncrWithTags(string, []string, float64) error
	Gauge(string, float64, float64) error
	Histogram(string, float64, float64) error
	HistogramWithTags(string, float64, []string, float64) error
	Timing(string, time.Duration, float64) error
	TimingWithTags(string, time.Duration, float64, []string) error
	StatsdClient() statsd.ClientInterface
	SetStarted()
}

// NewMetricsClient creates a new MetricsClient with the provided statsd address and
// namespace.
func NewMetricsClient(addr, namespace string) (*MetricsClient, error) {
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

	return &MetricsClient{
		metricsTags:  metricsTags,
		statsdClient: c,
	}, nil
}

// NewNoOpMetricsClient returns a MetricsClient with a no-op statsd client. This can
// be used when there's no statsd service available to smokescreen.
func NewNoOpMetricsClient() *MetricsClient {
	// Populate the client's map to hold metric tags
	metricsTags := make(map[string][]string)
	for _, m := range metrics {
		metricsTags[m] = []string{}
	}

	return &MetricsClient{
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
// *every* metric `foo` that is emitted for the lifetime of the MetricsClient.
//
// This function is not thread safe, and adding persitent tags should only be done while initializing
// the configuration and prior to running smokescreen.
func (mc *MetricsClient) AddMetricTags(metric string, mTags []string) error {
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics tags after starting smokescreen")
	}
	if tags, ok := mc.metricsTags[metric]; ok {
		mc.metricsTags[metric] = append(tags, mTags...)
		return nil
	}
	return fmt.Errorf("unknown metric: %s", metric)
}

// GetMetricTags returns the slice of metrics associated with a given metric.
func (mc *MetricsClient) GetMetricTags(metric string) []string {
	if tags, ok := mc.metricsTags[metric]; ok {
		return tags
	}
	return nil
}

func (mc *MetricsClient) Incr(metric string, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Incr(metric, mTags, rate)
}

func (mc *MetricsClient) IncrWithTags(metric string, tags []string, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	tags = append(tags, mTags...)
	return mc.statsdClient.Incr(metric, tags, rate)
}

func (mc *MetricsClient) Gauge(metric string, value float64, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Gauge(metric, value, mTags, rate)
}

func (mc *MetricsClient) Histogram(metric string, value float64, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Histogram(metric, value, mTags, rate)
}

func (mc *MetricsClient) HistogramWithTags(metric string, value float64, tags []string, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	tags = append(tags, mTags...)
	return mc.statsdClient.Histogram(metric, value, tags, rate)
}

func (mc *MetricsClient) Timing(metric string, d time.Duration, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	return mc.statsdClient.Timing(metric, d, mTags, rate)
}

func (mc *MetricsClient) TimingWithTags(metric string, d time.Duration, rate float64, tags []string) error {
	mTags := mc.GetMetricTags(metric)
	tags = append(tags, mTags...)
	return mc.statsdClient.Timing(metric, d, tags, rate)
}

func (mc *MetricsClient) StatsdClient() statsd.ClientInterface {
	return mc.statsdClient
}

func (mc *MetricsClient) SetStarted() {
	mc.started.Store(true)
}

// MetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &MetricsClient{}

// reportConnError emits a detailed metric about a connection error, with a tag corresponding to
// the failure type. If err is not a net.Error, does nothing.
func ReportConnError(mc MetricsClientInterface, err error) {
	e, ok := err.(net.Error)
	if !ok {
		return
	}

	etag := "type:unknown"
	switch {
	case e.Timeout():
		etag = "type:timeout"
	case errors.Is(e, syscall.ECONNREFUSED):
		etag = "type:refused"
	case errors.Is(e, syscall.ECONNRESET):
		etag = "type:reset"
	case errors.Is(e, syscall.ECONNABORTED):
		etag = "type:aborted"
	}

	mc.IncrWithTags("cn.atpt.connect.err", []string{etag}, 1)
}
