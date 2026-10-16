//go:build !smokescreen_no_prometheus

package metrics

import (
	"fmt"
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
	format      string
	endpoint    string
	metricsTags map[string]map[string]string
	mu          sync.RWMutex
	started     atomic.Value
	globalTags  atomic.Value // Immutable map[string]string snapshot.

	counters   map[string]prometheus.CounterVec
	gauges     map[string]prometheus.GaugeVec
	histograms map[string]prometheus.HistogramVec
	timings    map[string]prometheus.HistogramVec
}

// NewPrometheusMetricsClient exposes legacy metrics by default. An optional
// format argument selects "legacy", "dual", or "v2" for the lifetime of the client.
func NewPrometheusMetricsClient(endpoint string, port string, listenAddr string, formats ...string) (*PrometheusMetricsClient, error) {
	format := "legacy"
	if len(formats) > 1 {
		return nil, fmt.Errorf("expected at most one Prometheus metrics format")
	}
	if len(formats) == 1 {
		format = formats[0]
	}
	if format != "legacy" && format != "dual" && format != "v2" {
		return nil, fmt.Errorf("unknown Prometheus metrics format: %q", format)
	}
	metricsTags := make(map[string]map[string]string)
	for _, m := range metrics {
		metricsTags[m] = map[string]string{}
	}

	mc := &PrometheusMetricsClient{
		format:      format,
		metricsTags: metricsTags,
		endpoint:    endpoint,
		counters:    map[string]prometheus.CounterVec{},
		gauges:      map[string]prometheus.GaugeVec{},
		histograms:  map[string]prometheus.HistogramVec{},
		timings:     map[string]prometheus.HistogramVec{},
	}
	mux := http.NewServeMux()
	mux.Handle(endpoint, prometheusHandler(mc, prometheus.DefaultGatherer))
	go http.ListenAndServe(fmt.Sprintf("%s:%s", listenAddr, port), mux)
	return mc, nil
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
	tags := copyStringMap(additionalTags)
	mergeMaps(tags, mc.GetMetricTags(metric))
	for _, format := range mc.emissionFormats() {
		mc.incrementPrometheusCounter(metric, tags, format)
	}

	return nil
}

func (mc *PrometheusMetricsClient) Gauge(
	metric string,
	value float64,
	_ float64) error {
	baseTags := copyStringMap(mc.GetMetricTags(metric))
	for _, format := range mc.emissionFormats() {
		mc.updatePrometheusGauge(metric, value, baseTags, format)
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
	tags := copyStringMap(additionalTags)
	mergeMaps(tags, mc.GetMetricTags(metric))
	for _, format := range mc.emissionFormats() {
		mc.observeValuePrometheusHistogram(metric, value, tags, format)
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
	tags := copyStringMap(additionalTags)
	mergeMaps(tags, mc.GetMetricTags(metric))
	for _, format := range mc.emissionFormats() {
		mc.observeValuePrometheusTimer(metric, d, tags, format)
	}

	return nil
}

func (mc *PrometheusMetricsClient) SetStarted() {
	mc.started.Store(true)
}

// PrometheusMetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &PrometheusMetricsClient{}

func (mc *PrometheusMetricsClient) incrementPrometheusCounter(
	metric string,
	tags map[string]string,
	format string) {
	name := mc.metricName(metric, "counter", format)
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
		counter = *promauto.NewCounterVec(prometheus.CounterOpts{
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
	format string) {
	name := mc.metricName(metric, "gauge", format)
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
		gauge = *promauto.NewGaugeVec(prometheus.GaugeOpts{
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
	format string) {
	name := mc.metricName(metric, "histogram", format)
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
		histogram = *promauto.NewHistogramVec(prometheus.HistogramOpts{
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
	format string) {
	timerMetric := mc.metricName(metric, "timer", format)
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
		histogram = *promauto.NewHistogramVec(prometheus.HistogramOpts{
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

func mergeMaps[T comparable, U any](leftMap map[T]U, rightMap map[T]U) {
	for k, v := range rightMap {
		leftMap[k] = v
	}
}

func copyStringMap(input map[string]string) map[string]string {
	copy := make(map[string]string, len(input))
	for key, value := range input {
		copy[key] = value
	}
	return copy
}

func sanitisePrometheusMetricName(metric string) string {
	return strings.ReplaceAll(metric, ".", "_")
}
