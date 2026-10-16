//go:build !smokescreen_no_prometheus

package metrics

import (
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/common/model"
)

type prometheusMetricKind uint8

const (
	prometheusCounterKind prometheusMetricKind = iota
	prometheusGaugeKind
	prometheusHistogramKind
	prometheusTimerKind
)

type prometheusMetricOutput struct {
	name   string
	format string
}

type prometheusMetricNameSet struct {
	regular      [3]prometheusMetricOutput
	regularCount uint8
	timers       [3]prometheusMetricOutput
	timerCount   uint8
}

func (set *prometheusMetricNameSet) forKind(kind prometheusMetricKind) (*[3]prometheusMetricOutput, uint8) {
	if kind == prometheusTimerKind {
		return &set.timers, set.timerCount
	}
	return &set.regular, set.regularCount
}

func (set *prometheusMetricNameSet) setForKind(kind prometheusMetricKind, outputs [3]prometheusMetricOutput, count uint8) {
	if kind == prometheusTimerKind {
		set.timers, set.timerCount = outputs, count
		return
	}
	set.regular, set.regularCount = outputs, count
}

func compilePrometheusMetricNameOverrides(format string, overrides map[string]MetricNameOverride) (map[string]*prometheusMetricNameSet, error) {
	if len(overrides) == 0 {
		return nil, nil
	}

	for metric, override := range overrides {
		if !model.LegacyValidation.IsValidMetricName(override.Name) {
			return nil, fmt.Errorf("invalid Prometheus metric name override for %q: %q", metric, override.Name)
		}
	}

	compiled := make(map[string]*prometheusMetricNameSet, len(metrics))
	for _, metric := range metrics {
		override, hasOverride := overrides[metric]
		nameSet := &prometheusMetricNameSet{}
		regularOutputs, regularCount := prometheusOutputsForMetric(metric, prometheusCounterKind, format, override, hasOverride)
		nameSet.setForKind(prometheusCounterKind, regularOutputs, regularCount)
		timerOutputs, timerCount := prometheusOutputsForMetric(metric, prometheusTimerKind, format, override, hasOverride)
		nameSet.setForKind(prometheusTimerKind, timerOutputs, timerCount)
		compiled[metric] = nameSet
	}
	return compiled, nil
}

func prometheusOutputsForMetric(metric string, kind prometheusMetricKind, selectedFormat string, override MetricNameOverride, hasOverride bool) ([3]prometheusMetricOutput, uint8) {
	var outputs [3]prometheusMetricOutput
	var count uint8
	if !hasOverride || override.PublishAlongWithOriginal {
		if selectedFormat == "dual" {
			outputs[0] = prometheusMetricOutput{name: prometheusMetricName(metric, kind, "legacy"), format: "legacy"}
			outputs[1] = prometheusMetricOutput{name: prometheusMetricName(metric, kind, "v2"), format: "v2"}
			count = 2
		} else {
			outputs[0] = prometheusMetricOutput{name: prometheusMetricName(metric, kind, selectedFormat), format: selectedFormat}
			count = 1
		}
	}
	if hasOverride {
		customFormat := selectedFormat
		if customFormat == "dual" {
			customFormat = "v2"
		}
		custom := prometheusMetricOutput{name: override.Name, format: customFormat}
		duplicate := false
		for index := uint8(0); index < count; index++ {
			if outputs[index] == custom {
				duplicate = true
				break
			}
		}
		if !duplicate {
			outputs[count] = custom
			count++
		}
	}
	return outputs, count
}

func prometheusMetricName(metric string, kind prometheusMetricKind, format string) string {
	kindName := "counter"
	switch kind {
	case prometheusGaugeKind:
		kindName = "gauge"
	case prometheusHistogramKind:
		kindName = "histogram"
	case prometheusTimerKind:
		kindName = "timer"
	}
	if format == "v2" {
		if definition, ok := prometheusDefinitions[metric]; ok {
			return "smokescreen_" + definition.name
		}
		name := sanitisePrometheusMetricName(metric)
		if kindName == "counter" && !strings.HasSuffix(name, "_total") {
			name += "_total"
		}
		if kindName == "timer" && !strings.HasSuffix(name, "_seconds") {
			name += "_seconds"
		}
		return "smokescreen_" + name
	}
	name := sanitisePrometheusMetricName(metric)
	if kindName == "timer" {
		name += "_timer"
	}
	return name
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
