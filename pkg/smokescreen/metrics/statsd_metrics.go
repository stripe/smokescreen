package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/DataDog/datadog-go/v5/statsd"
)

type statsdMetricRow struct {
	names          [2]string
	nameCount      uint8
	persistentTags []string
	globalTags     []string // Global defaults not overridden by persistent tags.
	staticTags     []string // globalTags followed by persistentTags.
}

// StatsdMetricsClient is a thin wrapper around statsd.ClientInterface. It is used to allow
// adding arbitrary tags to Smokescreen metrics.
//
// StatsdMetricsClient is not thread safe for configuration and should only be configured before
// SetStarted. Emission methods may be called concurrently after configuration is complete.
type StatsdMetricsClient struct {
	metricRows   map[string]*statsdMetricRow
	namespace    string
	statsdClient statsd.ClientInterface
	started      atomic.Value
	globalTags   []string
}

// NewStatsdMetricsClient creates a new StatsdMetricsClient with the provided statsd address and
// namespace.
func NewStatsdMetricsClient(addr, namespace string) (*StatsdMetricsClient, error) {
	return NewStatsdMetricsClientWithOptions(addr, namespace, StatsdOptions{})
}

// NewStatsdMetricsClientWithOptions creates a StatsD client with optional complete output-name
// overrides keyed by canonical Smokescreen metric IDs.
func NewStatsdMetricsClientWithOptions(addr, namespace string, options StatsdOptions) (*StatsdMetricsClient, error) {
	overrides, err := copyMetricNameOverrides(options.Names)
	if err != nil {
		return nil, err
	}
	rows, err := buildStatsdMetricRows(namespace, overrides)
	if err != nil {
		return nil, err
	}

	c, err := statsd.New(
		addr,
		statsd.WithClientSideAggregation(),
		statsd.WithAggregationInterval(2*time.Second),
		statsd.WithoutOriginDetection(),
	)
	if err != nil {
		return nil, err
	}

	return &StatsdMetricsClient{
		metricRows:   rows,
		namespace:    namespace,
		statsdClient: c,
	}, nil
}

func buildStatsdMetricRows(namespace string, overrides map[string]MetricNameOverride) (map[string]*statsdMetricRow, error) {
	rows := make(map[string]*statsdMetricRow, len(metrics))
	usedNames := make(map[string]string, len(metrics)+len(overrides))
	for _, metric := range metrics {
		original := namespace + metric
		names := [2]string{original}
		count := uint8(1)
		if override, ok := overrides[metric]; ok {
			if err := validateStatsdMetricName(override.Name); err != nil {
				return nil, fmt.Errorf("invalid StatsD metric name override for %q: %w", metric, err)
			}
			if override.PublishAlongWithOriginal {
				names[1] = override.Name
				count = 2
			} else {
				names[0] = override.Name
			}
		}

		for index := uint8(0); index < count; index++ {
			name := names[index]
			if existingMetric, exists := usedNames[name]; exists {
				if existingMetric != metric {
					return nil, fmt.Errorf("StatsD metric name %q is used by both %q and %q", name, existingMetric, metric)
				}
				// An override may be identical to the metric's existing name.
				if index == 1 {
					count = 1
				}
				continue
			}
			usedNames[name] = metric
		}

		row := &statsdMetricRow{names: names, nameCount: count}
		rows[metric] = row
	}
	return rows, nil
}

func validateStatsdMetricName(name string) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	for _, character := range name {
		if character == ':' || character == '|' || unicode.IsControl(character) {
			return fmt.Errorf("name cannot contain colon, pipe, or control characters")
		}
	}
	return nil
}

// NewNoOpMetricsClient returns a StatsdMetricsClient with a no-op statsd client. This can
// be used when there's no statsd service available to smokescreen.
func NewNoOpMetricsClient() *StatsdMetricsClient {
	rows, _ := buildStatsdMetricRows("", nil)
	return &StatsdMetricsClient{
		metricRows:   rows,
		statsdClient: &statsd.NoOpClient{},
	}
}

// AddMetricTags associates the provided tags with a given canonical metric ID. The tags are
// attached to every emission of that metric for the lifetime of the client.
//
// This function is not thread safe. Add persistent tags during initialization, before
// SetStarted.
func (mc *StatsdMetricsClient) AddMetricTags(metric string, additionalTags map[string]string) error {
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics baseTags after starting smokescreen")
	}
	if row, ok := mc.metricRows[metric]; ok {
		row.persistentTags = append(row.persistentTags, constructTagArray(additionalTags)...)
		row.rebuildStaticTags(mc.globalTags)
		return nil
	}
	return fmt.Errorf("unknown metric: %s", metric)
}

func (mc *StatsdMetricsClient) SetGlobalMetricTags(tags map[string]string) error {
	copy, err := CopyAndValidateGlobalMetricTags(tags)
	if err != nil {
		return err
	}
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot set global metrics tags after starting smokescreen")
	}
	globalTags := constructTagArray(copy)
	mc.globalTags = globalTags
	for _, row := range mc.metricRows {
		row.rebuildStaticTags(globalTags)
	}
	return nil
}

func (row *statsdMetricRow) rebuildStaticTags(globalTags []string) {
	persistentKeys := make(map[string]struct{}, len(row.persistentTags))
	for _, tag := range row.persistentTags {
		key, _, _ := strings.Cut(tag, ":")
		persistentKeys[key] = struct{}{}
	}

	row.globalTags = make([]string, 0, len(globalTags))
	for _, tag := range globalTags {
		key, _, _ := strings.Cut(tag, ":")
		if _, overridden := persistentKeys[key]; !overridden {
			row.globalTags = append(row.globalTags, tag)
		}
	}
	row.staticTags = make([]string, 0, len(row.globalTags)+len(row.persistentTags))
	row.staticTags = append(row.staticTags, row.globalTags...)
	row.staticTags = append(row.staticTags, row.persistentTags...)
}

// GetMetricTags returns a defensive copy of the persistent tags for a canonical metric ID.
// Mutating the returned slice does not affect future metric emissions.
func (mc *StatsdMetricsClient) GetMetricTags(metric string) []string {
	if row, ok := mc.metricRows[metric]; ok {
		return append([]string(nil), row.persistentTags...)
	}
	return nil
}

func (mc *StatsdMetricsClient) prepareEmission(metric string, dynamicTags map[string]string) ([2]string, uint8, []string) {
	if row, ok := mc.metricRows[metric]; ok {
		return row.names, row.nameCount, row.tagsFor(dynamicTags)
	}
	name := mc.namespace + metric
	return [2]string{name}, 1, mc.fallbackTags(dynamicTags)
}

func (row *statsdMetricRow) tagsFor(dynamicTags map[string]string) []string {
	if len(dynamicTags) == 0 {
		return row.staticTags
	}
	tags := make([]string, 0, len(row.globalTags)+len(dynamicTags)+len(row.persistentTags))
	for _, tag := range row.globalTags {
		key, _, _ := strings.Cut(tag, ":")
		if _, overridden := dynamicTags[key]; !overridden {
			tags = append(tags, tag)
		}
	}
	for key, value := range dynamicTags {
		tags = append(tags, key+":"+value)
	}
	return append(tags, row.persistentTags...)
}

func (mc *StatsdMetricsClient) fallbackTags(dynamicTags map[string]string) []string {
	if len(dynamicTags) == 0 {
		return mc.globalTags
	}
	tags := make([]string, 0, len(mc.globalTags)+len(dynamicTags))
	for _, tag := range mc.globalTags {
		key, _, _ := strings.Cut(tag, ":")
		if _, overridden := dynamicTags[key]; !overridden {
			tags = append(tags, tag)
		}
	}
	for key, value := range dynamicTags {
		tags = append(tags, key+":"+value)
	}
	return tags
}

func (mc *StatsdMetricsClient) Incr(metric string, rate float64) error {
	return mc.IncrWithTags(metric, nil, rate)
}

func (mc *StatsdMetricsClient) IncrWithTags(metric string, additionalTags map[string]string, rate float64) error {
	names, count, tags := mc.prepareEmission(metric, additionalTags)
	var firstErr error
	for index := uint8(0); index < count; index++ {
		if err := mc.statsdClient.Incr(names[index], tags, rate); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *StatsdMetricsClient) Gauge(metric string, value float64, rate float64) error {
	names, count, tags := mc.prepareEmission(metric, nil)
	var firstErr error
	for index := uint8(0); index < count; index++ {
		if err := mc.statsdClient.Gauge(names[index], value, tags, rate); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *StatsdMetricsClient) Histogram(metric string, value float64, rate float64) error {
	return mc.HistogramWithTags(metric, value, nil, rate)
}

func (mc *StatsdMetricsClient) HistogramWithTags(metric string, value float64, additionalTags map[string]string, rate float64) error {
	names, count, tags := mc.prepareEmission(metric, additionalTags)
	var firstErr error
	for index := uint8(0); index < count; index++ {
		if err := mc.statsdClient.Histogram(names[index], value, tags, rate); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *StatsdMetricsClient) Timing(metric string, d time.Duration, rate float64) error {
	return mc.TimingWithTags(metric, d, nil, rate)
}

func (mc *StatsdMetricsClient) TimingWithTags(metric string, d time.Duration, additionalTags map[string]string, rate float64) error {
	names, count, tags := mc.prepareEmission(metric, additionalTags)
	var firstErr error
	for index := uint8(0); index < count; index++ {
		if err := mc.statsdClient.Timing(names[index], d, tags, rate); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *StatsdMetricsClient) StatsdClient() statsd.ClientInterface {
	return mc.statsdClient
}

func (mc *StatsdMetricsClient) SetStarted() {
	mc.started.Store(true)
}

// StatsdMetricsClient implements MetricsClientInterface.
var _ MetricsClientInterface = &StatsdMetricsClient{}

func constructTagArray(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	tagArray := make([]string, 0, len(tags))
	for key, value := range tags {
		tagArray = append(tagArray, key+":"+value)
	}
	return tagArray
}
