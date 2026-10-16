//go:build !smokescreen_no_prometheus

package metrics

import (
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

// PrometheusMetricsClient attempts to replicate the functionality of the StatsdMetricsClient, but exposing
// the metrics via a http endpoint
type PrometheusMetricsClient struct {
	format        string
	endpoint      string
	metricsTags   map[string]map[string]string
	nameOverrides map[string]*prometheusMetricNameSet
	mu            sync.RWMutex
	started       atomic.Value
	globalTags    atomic.Value // Immutable map[string]string snapshot.
	registerer    prometheus.Registerer

	counters   map[string]prometheus.CounterVec
	gauges     map[string]prometheus.GaugeVec
	histograms map[string]prometheus.HistogramVec
	timings    map[string]prometheus.HistogramVec
}

// NewPrometheusMetricsClient exposes legacy metrics by default. An optional
// format argument selects "legacy", "dual", or "v2" for the lifetime of the client.
func NewPrometheusMetricsClient(endpoint string, port string, listenAddr string, formats ...string) (*PrometheusMetricsClient, error) {
	if len(formats) > 1 {
		return nil, fmt.Errorf("expected at most one Prometheus metrics format")
	}
	format := "legacy"
	if len(formats) == 1 {
		format = formats[0]
		if format == "" {
			return nil, fmt.Errorf("unknown Prometheus metrics format: %q", format)
		}
	}
	return NewPrometheusMetricsClientWithOptions(endpoint, port, listenAddr, PrometheusOptions{Format: format})
}

func NewPrometheusMetricsClientWithOptions(endpoint string, port string, listenAddr string, options PrometheusOptions) (*PrometheusMetricsClient, error) {
	format := options.Format
	if format == "" {
		format = "legacy"
	}
	if format != "legacy" && format != "dual" && format != "v2" {
		return nil, fmt.Errorf("unknown Prometheus metrics format: %q", format)
	}
	overrides, err := copyMetricNameOverrides(options.Names)
	if err != nil {
		return nil, err
	}
	compiledOverrides, err := compilePrometheusMetricNameOverrides(format, overrides)
	if err != nil {
		return nil, err
	}
	mc := newPrometheusMetricsClient(format, compiledOverrides)
	mc.endpoint = endpoint
	mux := http.NewServeMux()
	mux.Handle(endpoint, prometheusHandler(mc, prometheus.DefaultGatherer))
	go http.ListenAndServe(fmt.Sprintf("%s:%s", listenAddr, port), mux)
	return mc, nil
}

func newPrometheusMetricsClient(format string, overrides map[string]*prometheusMetricNameSet) *PrometheusMetricsClient {
	metricsTags := make(map[string]map[string]string)
	for _, m := range metrics {
		metricsTags[m] = map[string]string{}
	}

	return &PrometheusMetricsClient{
		format:        format,
		metricsTags:   metricsTags,
		nameOverrides: overrides,
		registerer:    prometheus.DefaultRegisterer,
		counters:      map[string]prometheus.CounterVec{},
		gauges:        map[string]prometheus.GaugeVec{},
		histograms:    map[string]prometheus.HistogramVec{},
		timings:       map[string]prometheus.HistogramVec{},
	}
}

func prometheusHandler(mc *PrometheusMetricsClient, gatherer prometheus.Gatherer) http.Handler {
	return promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer,
		promhttp.HandlerFor(globalTagsGatherer{client: mc, gatherer: gatherer}, promhttp.HandlerOpts{}),
	)
}

type globalTagsGatherer struct {
	client   *PrometheusMetricsClient
	gatherer prometheus.Gatherer
}

func (g globalTagsGatherer) Gather() ([]*dto.MetricFamily, error) {
	var globalTags map[string]string
	if tags := g.client.globalTags.Load(); tags != nil {
		globalTags = tags.(map[string]string)
	}
	metricFamilies, err := g.gatherer.Gather()
	if len(globalTags) == 0 {
		return metricFamilies, err
	}

	clonedFamilies := make([]*dto.MetricFamily, len(metricFamilies))
	for index, family := range metricFamilies {
		cloned := proto.Clone(family).(*dto.MetricFamily)
		for _, metric := range cloned.Metric {
			existing := make(map[string]struct{}, len(metric.Label))
			for _, label := range metric.Label {
				existing[label.GetName()] = struct{}{}
			}
			for name, value := range globalTags {
				if _, exists := existing[name]; exists {
					continue
				}
				metric.Label = append(metric.Label, &dto.LabelPair{Name: proto.String(name), Value: proto.String(value)})
			}
			sort.Slice(metric.Label, func(i, j int) bool {
				return metric.Label[i].GetName() < metric.Label[j].GetName()
			})
		}
		clonedFamilies[index] = cloned
	}
	return clonedFamilies, err
}

func (mc *PrometheusMetricsClient) SetGlobalMetricTags(tags map[string]string) error {
	copy, err := CopyAndValidateGlobalMetricTags(tags)
	if err != nil {
		return err
	}
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot set global metrics tags after starting smokescreen")
	}
	mc.globalTags.Store(copy)
	return nil
}

func (mc *PrometheusMetricsClient) AddMetricTags(
	metric string,
	additionalTags map[string]string) error {
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics tags after starting smokescreen")
	}
	if _, ok := mc.metricsTags[metric]; ok {
		for k, v := range additionalTags {
			mc.metricsTags[metric][k] = v
		}
		return nil
	}
	return fmt.Errorf("unknown metric: %s", metric)
}

func (mc *PrometheusMetricsClient) GetMetricTags(metric string) map[string]string {
	if tags, ok := mc.metricsTags[metric]; ok {
		return tags
	}
	return nil
}

func (mc *PrometheusMetricsClient) Incr(
	metric string,
	rate float64) error {
	return mc.IncrWithTags(metric, map[string]string{}, rate)
}

func (mc *PrometheusMetricsClient) IncrWithTags(
	metric string,
	additionalTags map[string]string,
	_ float64) error {
	tags := make(map[string]string, len(additionalTags))
	maps.Copy(tags, additionalTags)
	maps.Copy(tags, mc.GetMetricTags(metric))
	if names, count, ok := mc.emissionNames(metric, prometheusCounterKind); ok {
		for index := uint8(0); index < count; index++ {
			output := names[index]
			mc.incrementPrometheusCounter(metric, tags, output.name, output.format)
		}
		return nil
	}
	for _, format := range mc.emissionFormats() {
		mc.incrementPrometheusCounter(metric, tags, prometheusMetricName(metric, prometheusCounterKind, format), format)
	}

	return nil
}

func (mc *PrometheusMetricsClient) Gauge(
	metric string,
	value float64,
	_ float64) error {
	baseTags := maps.Clone(mc.GetMetricTags(metric))
	if names, count, ok := mc.emissionNames(metric, prometheusGaugeKind); ok {
		for index := uint8(0); index < count; index++ {
			output := names[index]
			mc.updatePrometheusGauge(metric, value, baseTags, output.name, output.format)
		}
		return nil
	}
	for _, format := range mc.emissionFormats() {
		mc.updatePrometheusGauge(metric, value, baseTags, prometheusMetricName(metric, prometheusGaugeKind, format), format)
	}

	return nil
}

func (mc *PrometheusMetricsClient) Histogram(
	metric string,
	value float64,
	rate float64) error {
	return mc.HistogramWithTags(metric, value, map[string]string{}, rate)
}

func (mc *PrometheusMetricsClient) HistogramWithTags(
	metric string,
	value float64,
	additionalTags map[string]string,
	_ float64) error {
	tags := make(map[string]string, len(additionalTags))
	maps.Copy(tags, additionalTags)
	maps.Copy(tags, mc.GetMetricTags(metric))
	if names, count, ok := mc.emissionNames(metric, prometheusHistogramKind); ok {
		for index := uint8(0); index < count; index++ {
			output := names[index]
			mc.observeValuePrometheusHistogram(metric, value, tags, output.name, output.format)
		}
		return nil
	}
	for _, format := range mc.emissionFormats() {
		mc.observeValuePrometheusHistogram(metric, value, tags, prometheusMetricName(metric, prometheusHistogramKind, format), format)
	}

	return nil
}

func (mc *PrometheusMetricsClient) Timing(
	metric string,
	duration time.Duration,
	rate float64) error {
	return mc.TimingWithTags(metric, duration, map[string]string{}, rate)
}

func (mc *PrometheusMetricsClient) TimingWithTags(
	metric string,
	d time.Duration,
	additionalTags map[string]string,
	_ float64) error {
	tags := make(map[string]string, len(additionalTags))
	maps.Copy(tags, additionalTags)
	maps.Copy(tags, mc.GetMetricTags(metric))
	if names, count, ok := mc.emissionNames(metric, prometheusTimerKind); ok {
		for index := uint8(0); index < count; index++ {
			output := names[index]
			mc.observeValuePrometheusTimer(metric, d, tags, output.name, output.format)
		}
		return nil
	}
	for _, format := range mc.emissionFormats() {
		mc.observeValuePrometheusTimer(metric, d, tags, prometheusMetricName(metric, prometheusTimerKind, format), format)
	}

	return nil
}

func (mc *PrometheusMetricsClient) SetStarted() {
	mc.started.Store(true)
}

func (mc *PrometheusMetricsClient) emissionNames(metric string, kind prometheusMetricKind) (*[3]prometheusMetricOutput, uint8, bool) {
	outputs, ok := mc.nameOverrides[metric]
	if !ok {
		return nil, 0, false
	}
	names, count := outputs.forKind(kind)
	return names, count, true
}

// PrometheusMetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &PrometheusMetricsClient{}

func (mc *PrometheusMetricsClient) incrementPrometheusCounter(
	metric string,
	tags map[string]string,
	name string,
	format string) {
	mc.mu.RLock()
	counter, ok := mc.counters[name]
	mc.mu.RUnlock()

	if ok {
		counter.With(tags).Inc()
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if counter, ok = mc.counters[name]; !ok {
		counter = *promauto.With(mc.registerer).NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: mc.metricHelp(metric, format),
		}, mapKeys(tags))
		mc.counters[name] = counter
	}
	mc.mu.Unlock()

	counter.With(tags).Inc()
}

func (mc *PrometheusMetricsClient) updatePrometheusGauge(
	metric string,
	value float64,
	tags map[string]string,
	name string,
	format string) {
	mc.mu.RLock()
	gauge, ok := mc.gauges[name]
	mc.mu.RUnlock()

	if ok {
		gauge.With(tags).Set(value)
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if gauge, ok = mc.gauges[name]; !ok {
		gauge = *promauto.With(mc.registerer).NewGaugeVec(prometheus.GaugeOpts{
			Name: name,
			Help: mc.metricHelp(metric, format),
		}, mapKeys(tags))
		mc.gauges[name] = gauge
	}
	mc.mu.Unlock()

	gauge.With(tags).Set(value)
}

func (mc *PrometheusMetricsClient) observeValuePrometheusHistogram(
	metric string,
	value float64,
	tags map[string]string,
	name string,
	format string) {
	mc.mu.RLock()
	histogram, ok := mc.histograms[name]
	mc.mu.RUnlock()

	if ok {
		histogram.With(tags).Observe(value)
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if histogram, ok = mc.histograms[name]; !ok {
		histogram = *promauto.With(mc.registerer).NewHistogramVec(prometheus.HistogramOpts{
			Name:    name,
			Help:    mc.metricHelp(metric, format),
			Buckets: mc.metricBuckets(metric, format),
		}, mapKeys(tags))
		mc.histograms[name] = histogram
	}
	mc.mu.Unlock()

	histogram.With(tags).Observe(value)
}

func (mc *PrometheusMetricsClient) observeValuePrometheusTimer(
	metric string,
	duration time.Duration,
	tags map[string]string,
	timerMetric string,
	format string) {
	mc.mu.RLock()
	histogram, ok := mc.timings[timerMetric]
	mc.mu.RUnlock()

	if ok {
		histogram.With(tags).Observe(mc.timerValue(duration, format))
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if histogram, ok = mc.timings[timerMetric]; !ok {
		histogram = *promauto.With(mc.registerer).NewHistogramVec(prometheus.HistogramOpts{
			Name:    timerMetric,
			Help:    mc.metricHelp(metric, format),
			Buckets: mc.metricBuckets(metric, format),
		}, mapKeys(tags))
		mc.timings[timerMetric] = histogram
	}
	mc.mu.Unlock()

	histogram.With(tags).Observe(mc.timerValue(duration, format))
}

func mapKeys[T comparable, U any](inputMap map[T]U) []T {
	var keys []T
	for k := range inputMap {
		keys = append(keys, k)
	}
	return keys
}

func sanitisePrometheusMetricName(metric string) string {
	return strings.ReplaceAll(metric, ".", "_")
}
