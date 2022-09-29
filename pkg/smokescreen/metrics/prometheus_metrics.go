package metrics

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"strings"
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
	timings    map[string]prometheus.HistogramVec
}

func NewPrometheusMetricsClient(endpoint string) (*PrometheusMetricsClient, error) {
	http.Handle(endpoint, promhttp.Handler())
	go http.ListenAndServe(":2112", nil)

	metricsTags := make(map[string]map[string]string)
	for _, m := range Metrics {
		metricsTags[m] = map[string]string{}
	}

	return &PrometheusMetricsClient{
		metricsTags: metricsTags,
		endpoint:    endpoint,
		counters:    map[string]prometheus.CounterVec{},
		gauges:      map[string]prometheus.GaugeVec{},
		histograms:  map[string]prometheus.HistogramVec{},
		timings:     map[string]prometheus.HistogramVec{},
	}, nil
}

func (mc *PrometheusMetricsClient) AddMetricTags(
	metric string,
	mTags map[string]string) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics tags after starting smokescreen")
	}
	if _, ok := mc.metricsTags[sanitisedMetric]; ok {
		for k, v := range mTags {
			mc.metricsTags[sanitisedMetric][k] = v
		}
		return nil
	}
	return fmt.Errorf("unknown metric: %s", metric)
}

func (mc *PrometheusMetricsClient) GetMetricTags(metric string) map[string]string {
	sanitisedMetric := sanitisePrometheusMetricName(metric)
	if tags, ok := mc.metricsTags[sanitisedMetric]; ok {
		return tags
	}
	return nil
}

func (mc *PrometheusMetricsClient) Incr(
	metric string,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)
	baseTags := mc.GetMetricTags(sanitisedMetric)
	mc.incrementPrometheusCounter(sanitisedMetric, baseTags)
	return nil
}

func (mc *PrometheusMetricsClient) IncrWithTags(
	metric string,
	tags map[string]string,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mergeMaps(tags, baseTags)
	mc.incrementPrometheusCounter(sanitisedMetric, tags)

	return nil
}

func (mc *PrometheusMetricsClient) Gauge(
	metric string,
	value float64,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mc.updatePrometheusGauge(sanitisedMetric, value, baseTags)

	return nil
}

func (mc *PrometheusMetricsClient) Histogram(
	metric string,
	value float64,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mc.observeValuePrometheusHistogram(sanitisedMetric, value, baseTags)

	return nil
}

func (mc *PrometheusMetricsClient) HistogramWithTags(
	metric string,
	value float64,
	tags map[string]string,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mergeMaps(tags, baseTags)
	mc.observeValuePrometheusHistogram(sanitisedMetric, value, tags)

	return nil
}

func (mc *PrometheusMetricsClient) Timing(
	metric string,
	duration time.Duration,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mc.observeValuePrometheusTimer(sanitisedMetric, duration, baseTags)

	return nil
}

func (mc *PrometheusMetricsClient) TimingWithTags(
	metric string,
	d time.Duration,
	_ float64,
	tags map[string]string) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mergeMaps(tags, baseTags)
	mc.observeValuePrometheusTimer(sanitisedMetric, d, tags)

	return nil
}

func (mc *PrometheusMetricsClient) SetStarted() {
	mc.started.Store(true)
}

// PrometheusMetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &PrometheusMetricsClient{}

func (mc *PrometheusMetricsClient) incrementPrometheusCounter(metric string, tags map[string]string) {
	if existingCounter, ok := mc.counters[metric]; ok {
		existingCounter.With(tags).Inc()
	} else {
		counter := promauto.NewCounterVec(prometheus.CounterOpts{
			Name: metric,
		}, mapKeys(tags))
		counter.With(tags).Inc()
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

func (mc *PrometheusMetricsClient) observeValuePrometheusTimer(
	metric string,
	duration time.Duration,
	tags map[string]string) {
	if existingHistogram, ok := mc.timings[metric]; ok {
		existingHistogram.With(tags).Observe(float64(duration.Milliseconds()))
	} else {
		histogram := promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name: metric,
		}, mapKeys(tags))

		histogram.With(tags).Observe(float64(duration.Milliseconds()))
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

func sanitisePrometheusMetricName(metric string) string {
	return strings.ReplaceAll(metric, ".", "_")
}
