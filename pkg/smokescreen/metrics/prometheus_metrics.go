package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusMetricsClient attempts to replicate the functionality of the StatsdMetricsClient, but exposing
// the metrics via a http endpoint
type PrometheusMetricsClient struct {
	endpoint    string
	metricsTags map[string]map[string]string
	mu          sync.RWMutex
	started     atomic.Value

	counters   map[string]prometheus.CounterVec
	gauges     map[string]prometheus.GaugeVec
	histograms map[string]prometheus.HistogramVec
	timings    map[string]prometheus.HistogramVec
}

func NewPrometheusMetricsClient(endpoint string, port string, listenAddr string) (*PrometheusMetricsClient, error) {
	http.Handle(endpoint, promhttp.Handler())
	go http.ListenAndServe(fmt.Sprintf("%s:%s", listenAddr, port), nil)

	metricsTags := make(map[string]map[string]string)
	for _, m := range metrics {
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
	additionalTags map[string]string) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)
	if mc.started.Load() != nil {
		return fmt.Errorf("cannot add metrics tags after starting smokescreen")
	}
	if _, ok := mc.metricsTags[sanitisedMetric]; ok {
		for k, v := range additionalTags {
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
	rate float64) error {
	return mc.IncrWithTags(metric, map[string]string{}, rate)
}

func (mc *PrometheusMetricsClient) IncrWithTags(
	metric string,
	additionalTags map[string]string,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mergeMaps(additionalTags, baseTags)
	mc.incrementPrometheusCounter(sanitisedMetric, additionalTags)

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
	rate float64) error {
	return mc.HistogramWithTags(metric, value, map[string]string{}, rate)
}

func (mc *PrometheusMetricsClient) HistogramWithTags(
	metric string,
	value float64,
	additionalTags map[string]string,
	_ float64) error {
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mergeMaps(additionalTags, baseTags)
	mc.observeValuePrometheusHistogram(sanitisedMetric, value, additionalTags)

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
	sanitisedMetric := sanitisePrometheusMetricName(metric)

	baseTags := mc.GetMetricTags(sanitisedMetric)
	mergeMaps(additionalTags, baseTags)
	mc.observeValuePrometheusTimer(sanitisedMetric, d, additionalTags)

	return nil
}

func (mc *PrometheusMetricsClient) SetStarted() {
	mc.started.Store(true)
}

// PrometheusMetricsClient implements MetricsClientInterface
var _ MetricsClientInterface = &PrometheusMetricsClient{}

func (mc *PrometheusMetricsClient) incrementPrometheusCounter(
	metric string,
	tags map[string]string) {
	mc.mu.RLock()
	counter, ok := mc.counters[metric]
	mc.mu.RUnlock()

	if ok {
		counter.With(tags).Inc()
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if counter, ok = mc.counters[metric]; !ok {
		counter = *promauto.NewCounterVec(prometheus.CounterOpts{
			Name: metric,
		}, mapKeys(tags))
		mc.counters[metric] = counter
	}
	mc.mu.Unlock()

	counter.With(tags).Inc()
}

func (mc *PrometheusMetricsClient) updatePrometheusGauge(
	metric string,
	value float64,
	tags map[string]string) {
	mc.mu.RLock()
	gauge, ok := mc.gauges[metric]
	mc.mu.RUnlock()

	if ok {
		gauge.With(tags).Set(value)
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if gauge, ok = mc.gauges[metric]; !ok {
		gauge = *promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: metric,
		}, mapKeys(tags))
		mc.gauges[metric] = gauge
	}
	mc.mu.Unlock()

	gauge.With(tags).Set(value)
}

func (mc *PrometheusMetricsClient) observeValuePrometheusHistogram(
	metric string,
	value float64,
	tags map[string]string) {
	mc.mu.RLock()
	histogram, ok := mc.histograms[metric]
	mc.mu.RUnlock()

	if ok {
		histogram.With(tags).Observe(value)
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if histogram, ok = mc.histograms[metric]; !ok {
		histogram = *promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name: metric,
		}, mapKeys(tags))
		mc.histograms[metric] = histogram
	}
	mc.mu.Unlock()

	histogram.With(tags).Observe(value)
}

func (mc *PrometheusMetricsClient) observeValuePrometheusTimer(
	metric string,
	duration time.Duration,
	tags map[string]string) {
	timerMetric := metric + "_timer"
	mc.mu.RLock()
	histogram, ok := mc.timings[timerMetric]
	mc.mu.RUnlock()

	if ok {
		histogram.With(tags).Observe(float64(duration.Milliseconds()))
		return
	}

	mc.mu.Lock()
	// double check just in case it was created between the RLock and Lock
	if histogram, ok = mc.timings[timerMetric]; !ok {
		histogram = *promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name: timerMetric,
		}, mapKeys(tags))
		mc.timings[timerMetric] = histogram
	}
	mc.mu.Unlock()

	histogram.With(tags).Observe(float64(duration.Milliseconds()))
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
