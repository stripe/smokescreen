package metrics

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"syscall"
	"time"
	"unicode"
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

// GlobalMetricTagsSetter is an optional capability implemented by the built-in
// metrics clients. It intentionally stays separate from MetricsClientInterface
// in Smokescreen v1 so existing custom clients remain source-compatible.
type GlobalMetricTagsSetter interface {
	SetGlobalMetricTags(map[string]string) error
}

var globalMetricTagName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func CopyAndValidateGlobalMetricTags(tags map[string]string) (map[string]string, error) {
	copied := make(map[string]string, len(tags))
	for key, value := range tags {
		if !globalMetricTagName.MatchString(key) || len(key) >= 2 && key[:2] == "__" {
			return nil, fmt.Errorf("invalid global metric tag key %q: keys must match [a-zA-Z_][a-zA-Z0-9_]* and cannot start with __", key)
		}
		if key == "le" || key == "quantile" {
			return nil, fmt.Errorf("invalid global metric tag key %q: reserved by Prometheus", key)
		}
		for _, char := range value {
			if char == ',' || char == '|' || unicode.IsControl(char) {
				return nil, fmt.Errorf("invalid value for global metric tag %q: values cannot contain comma, pipe, or control characters", key)
			}
		}
		copied[key] = value
	}
	return copied, nil
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
