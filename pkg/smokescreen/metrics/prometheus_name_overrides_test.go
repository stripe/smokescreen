//go:build !smokescreen_no_prometheus

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestPrometheusMetricNameOverrideValidation(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		override map[string]MetricNameOverride
		wantText string
	}{
		{name: "unknown metric", format: "v2", override: map[string]MetricNameOverride{"not.real": {Name: "custom_name"}}, wantText: "unknown metric"},
		{name: "invalid name", format: "v2", override: map[string]MetricNameOverride{"acl.allow": {Name: "not a name"}}, wantText: "invalid Prometheus metric name"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewPrometheusMetricsClientWithOptions("/metrics", "invalid", "127.0.0.1", PrometheusOptions{
				Format: test.format,
				Names:  test.override,
			})
			require.ErrorContains(t, err, test.wantText)
			require.Nil(t, client)
		})
	}
}

func TestPrometheusMetricNameOverridesPublishAliasesWithCorrectSemantics(t *testing.T) {
	overrides := map[string]MetricNameOverride{
		"acl.allow":            {Name: "metric_override_acl_allow_total", PublishAlongWithOriginal: true},
		"acl.deny":             {Name: "metric_override_acl_deny_total"},
		"requests.concurrent":  {Name: "metric_override_requests_concurrent", PublishAlongWithOriginal: true},
		"resolver.lookup_time": {Name: "metric_override_resolver_duration_seconds", PublishAlongWithOriginal: true},
		"cn.duration":          {Name: "metric_override_connection_duration_seconds", PublishAlongWithOriginal: true},
	}
	compiled, err := compilePrometheusMetricNameOverrides("dual", overrides)
	require.NoError(t, err)
	client, registry := newIsolatedPrometheusMetricsClient("dual", compiled)
	require.NoError(t, client.AddMetricTags("acl.allow", map[string]string{"team": "payments"}))
	require.NoError(t, client.SetGlobalMetricTags(map[string]string{"env": "prod", "team": "global"}))
	require.NoError(t, client.IncrWithTags("acl.allow", map[string]string{"region": "eu", "team": "dynamic"}, 1))
	require.NoError(t, client.Incr("acl.deny", 1))
	require.NoError(t, client.Gauge("requests.concurrent", 7, 1))
	require.NoError(t, client.Timing("resolver.lookup_time", 1500*time.Millisecond, 1))
	require.NoError(t, client.Histogram("cn.duration", 2.5, 1))

	families, err := globalTagsGatherer{client: client, gatherer: registry}.Gather()
	require.NoError(t, err)
	byName := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		byName[family.GetName()] = family
	}

	for _, name := range []string{
		"acl_allow", "smokescreen_acl_allow_total", "metric_override_acl_allow_total",
		"metric_override_acl_deny_total",
		"requests_concurrent", "smokescreen_requests_concurrent", "metric_override_requests_concurrent",
		"resolver_lookup_time_timer", "smokescreen_resolver_lookup_duration_seconds", "metric_override_resolver_duration_seconds",
		"cn_duration", "smokescreen_connection_duration_seconds", "metric_override_connection_duration_seconds",
	} {
		require.Contains(t, byName, name, "missing family %q", name)
	}
	require.NotContains(t, byName, "acl_deny")
	require.NotContains(t, byName, "smokescreen_acl_deny_total")

	for _, name := range []string{"acl_allow", "smokescreen_acl_allow_total", "metric_override_acl_allow_total"} {
		family := byName[name]
		require.Equal(t, dto.MetricType_COUNTER, family.GetType())
		require.Equal(t, float64(1), family.Metric[0].GetCounter().GetValue())
		labels := prometheusLabels(family.Metric[0])
		require.Equal(t, "payments", labels["team"])
		require.Equal(t, "eu", labels["region"])
		require.Equal(t, "prod", labels["env"])
	}

	for _, name := range []string{"resolver_lookup_time_timer", "smokescreen_resolver_lookup_duration_seconds", "metric_override_resolver_duration_seconds"} {
		require.Equal(t, dto.MetricType_HISTOGRAM, byName[name].GetType())
		value := byName[name].Metric[0].GetHistogram().GetSampleSum()
		if name == "resolver_lookup_time_timer" {
			require.Equal(t, float64(1500), value)
		} else {
			require.Equal(t, 1.5, value)
		}
	}

	for _, name := range []string{"cn_duration", "smokescreen_connection_duration_seconds", "metric_override_connection_duration_seconds"} {
		family := byName[name]
		require.Equal(t, dto.MetricType_HISTOGRAM, family.GetType())
		require.Equal(t, uint64(1), family.Metric[0].GetHistogram().GetSampleCount())
		if name != "cn_duration" {
			require.Contains(t, family.GetHelp(), "Duration of closed tracked connections")
		} else {
			require.Empty(t, family.GetHelp())
		}
	}
}

func newIsolatedPrometheusMetricsClient(format string, overrides map[string]*prometheusMetricNameSet) (*PrometheusMetricsClient, *prometheus.Registry) {
	registry := prometheus.NewRegistry()
	client := newPrometheusMetricsClient(format, overrides)
	client.registerer = registry
	return client, registry
}

func prometheusLabels(metric *dto.Metric) map[string]string {
	labels := make(map[string]string, len(metric.Label))
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}

func TestPrometheusMetricNameOverrideDeduplicatesSameName(t *testing.T) {
	compiled, err := compilePrometheusMetricNameOverrides("v2", map[string]MetricNameOverride{
		"acl.allow": {Name: "smokescreen_acl_allow_total", PublishAlongWithOriginal: true},
	})
	require.NoError(t, err)
	outputs, count, ok := newPrometheusMetricsClient("v2", compiled).emissionNames("acl.allow", prometheusCounterKind)
	require.True(t, ok)
	require.Equal(t, uint8(1), count)
	require.Equal(t, "smokescreen_acl_allow_total", outputs[0].name)
}
