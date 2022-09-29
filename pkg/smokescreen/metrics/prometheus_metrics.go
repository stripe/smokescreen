package metrics

import (
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"sync/atomic"
	"time"
)

// PrometheusMetricsClient attempts to replicate the functionality of the StatsdMetricsClient, but exposing
// the metrics via a http endpoint
type PrometheusMetricsClient struct {
	endpoint    string
	metricsTags map[string]map[string]string
	started     atomic.Value

	counters   map[string]prometheus.CounterVec
	gauges     map[string]prometheus.GaugeVec
	histograms map[string]prometheus.HistogramVec
	timings    map[string]prometheus.Timer
}

func NewPrometheusMetricsClient(endpoint string) (*PrometheusMetricsClient, error) {
	// TODO - Find where this should live
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":2112", nil)

	metricsTags := make(map[string]map[string]string)
	for _, m := range Metrics {
		metricsTags[m] = map[string]string{}
	}

	return &PrometheusMetricsClient{
		metricsTags: metricsTags,
		endpoint:    endpoint,
	}, nil
}

func (mc *PrometheusMetricsClient) AddMetricTags(
	metric string,
	mTags map[string]string) error {
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics tags after starting smokescreen")
	}
	if _, ok := mc.metricsTags[metric]; ok {
		for k, v := range mTags {
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
	_ float64) error {
	baseTags := mc.GetMetricTags(metric)
	mc.incrementPrometheusCounter(metric, baseTags)
	return nil
}

func (mc *PrometheusMetricsClient) IncrWithTags(
	metric string,
	tags map[string]string,
	_ float64) error {
	baseTags := mc.GetMetricTags(metric)
	mergeMaps(tags, baseTags)
	mc.incrementPrometheusCounter(metric, tags)
	return nil
}

func (mc *PrometheusMetricsClient) Gauge(
	metric string,
	value float64,
	_ float64) error {
	baseTags := mc.GetMetricTags(metric)
	mc.updatePrometheusGauge(metric, value, baseTags)
	return nil
}

func (mc *PrometheusMetricsClient) Histogram(
	metric string,
	value float64,
	_ float64) error {
	baseTags := mc.GetMetricTags(metric)
	mc.observeValuePrometheusHistogram(metric, value, baseTags)
	return nil
}

func (mc *PrometheusMetricsClient) HistogramWithTags(
	metric string,
	value float64,
	tags map[string]string,
	_ float64) error {
	baseTags := mc.GetMetricTags(metric)
	mergeMaps(tags, baseTags)
	mc.observeValuePrometheusHistogram(metric, value, tags)
	return nil
}

func (mc *PrometheusMetricsClient) Timing(
	metric string,
	d time.Duration,
	_ float64) error {
	// TODO - JMcC complete
	return errors.New("UNIMPLEMENTED")
}

func (mc *PrometheusMetricsClient) TimingWithTags(
	metric string,
	d time.Duration,
	_ float64,
	tags map[string]string) error {
	// TODO - JMcC complete
	return errors.New("UNIMPLEMENTED")
}

func (mc *PrometheusMetricsClient) SetStarted() {
	mc.started.Store(true)
}

// PrometheusMetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &PrometheusMetricsClient{}

func (mc *PrometheusMetricsClient) incrementPrometheusCounter(metric string, tags map[string]string) {
	if existingCounter, ok := mc.counters[metric]; ok {
		existingCounter.With(prometheus.Labels{}).Inc()
	} else {
		counter := promauto.NewCounterVec(prometheus.CounterOpts{
			Name: metric,
		}, mapKeys(tags))
		counter.With(prometheus.Labels{}).Inc()
		mc.counters[metric] = *counter
	}
}

func (mc *PrometheusMetricsClient) updatePrometheusGauge(
	metric string,
	value float64,
	tags map[string]string) {
	if existingGauge, ok := mc.gauges[metric]; ok {
		existingGauge.With(tags).Add(value)
	} else {
		gauge := promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: metric,
		}, mapKeys(tags))
		gauge.With(tags).Add(value)
		mc.gauges[metric] = *gauge
	}
}

func (mc *PrometheusMetricsClient) observeValuePrometheusHistogram(
	metric string,
	value float64,
	tags map[string]string) {
	if existingHistogram, ok := mc.histograms[metric]; ok {
		existingHistogram.With(tags).Observe(value)
	} else {
		histogram := promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name: metric,
		}, mapKeys(tags))
		histogram.With(tags).Observe(value)
		mc.histograms[metric] = *histogram
	}
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
