//go:build !smokescreen_no_prometheus

package metrics

import (
	"strings"
	"time"
)

func (mc *PrometheusMetricsClient) metricName(metric, kind, format string) string {
	if format != "v2" {
		name := sanitisePrometheusMetricName(metric)
		if kind == "timer" {
			name += "_timer"
		}
		return name
	}
	if def, ok := prometheusDefinitions[metric]; ok {
		return "smokescreen_" + def.name
	}
	name := sanitisePrometheusMetricName(metric)
	if kind == "counter" && !strings.HasSuffix(name, "_total") {
		name += "_total"
	}
	if kind == "timer" && !strings.HasSuffix(name, "_seconds") {
		name += "_seconds"
	}
	return "smokescreen_" + name
}

func (mc *PrometheusMetricsClient) metricHelp(metric, format string) string {
	if format != "v2" {
		return ""
	}
	if def, ok := prometheusDefinitions[metric]; ok {
		return def.help
	}
	return "Smokescreen " + metric + "."
}

func (mc *PrometheusMetricsClient) metricBuckets(metric, format string) []float64 {
	if format != "v2" {
		return nil
	}
	return prometheusDefinitions[metric].buckets
}

func (mc *PrometheusMetricsClient) timerValue(duration time.Duration, format string) float64 {
	if format == "v2" {
		return duration.Seconds()
	}
	return float64(duration.Milliseconds())
}

// emissionFormats selects collectors without changing the client's immutable format.
func (mc *PrometheusMetricsClient) emissionFormats() []string {
	if mc.format == "dual" {
		return []string{"legacy", "v2"}
	}
	return []string{mc.format}
}
