package metrics

import (
	"errors"
	"net"
	"regexp"
	"syscall"
	"time"
)

// metrics contains the internal metric names eligible for persistent tags.
var metrics = func() []string {
	names := make([]string, 0, len(prometheusDefinitions))
	for name := range prometheusDefinitions {
		names = append(names, name)
	}
	return names
}()

type MetricsClientInterface interface {
	AddMetricTags(string, map[string]string) error
	Incr(string, float64) error
	IncrWithTags(string, map[string]string, float64) error
	Gauge(string, float64, float64) error
	Histogram(string, float64, float64) error
	HistogramWithTags(string, float64, map[string]string, float64) error
	Timing(string, time.Duration, float64) error
	TimingWithTags(string, time.Duration, map[string]string, float64) error
	SetStarted()
}

// reportConnError emits a detailed metric about a connection error, with a tag corresponding to
// the failure type. If err is not a net.Error, does nothing.
func ReportConnError(mc MetricsClientInterface, err error) {
	e, ok := err.(net.Error)
	if !ok {
		return
	}

	errorTag := map[string]string{"type": "unknown"}
	switch {
	case e.Timeout():
		errorTag["type"] = "timeout"
	case errors.Is(e, syscall.ECONNREFUSED):
		errorTag["type"] = "refused"
	case errors.Is(e, syscall.ECONNRESET):
		errorTag["type"] = "reset"
	case errors.Is(e, syscall.ECONNABORTED):
		errorTag["type"] = "aborted"
	}

	mc.IncrWithTags("cn.atpt.connect.err", errorTag, 1)
}

// SanitizeTagValue sanitizes tag values to prevent injection attacks in both
// StatsD and Prometheus metrics. This removes or replaces characters that could
// be used to inject malicious content through metric tags.
func SanitizeTagValue(value string) string {
	dangerousChars := regexp.MustCompile(`[|@#:"}{\\[:cntrl:]]`)

	return dangerousChars.ReplaceAllString(value, "_")
}
