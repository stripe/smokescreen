package metrics

import (
	"net"
	"testing"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/stretchr/testify/require"
)

type capturedStatsdEmission struct {
	kind  string
	name  string
	value float64
	d     time.Duration
	rate  float64
	tags  []string
}

type capturedStatsdClient struct {
	statsd.ClientInterface
	emissions []capturedStatsdEmission
}

func (client *capturedStatsdClient) Incr(name string, tags []string, rate float64) error {
	client.emissions = append(client.emissions, capturedStatsdEmission{kind: "counter", name: name, value: 1, rate: rate, tags: append([]string(nil), tags...)})
	return nil
}

func (client *capturedStatsdClient) Gauge(name string, value float64, tags []string, rate float64) error {
	client.emissions = append(client.emissions, capturedStatsdEmission{kind: "gauge", name: name, value: value, rate: rate, tags: append([]string(nil), tags...)})
	return nil
}

func (client *capturedStatsdClient) Histogram(name string, value float64, tags []string, rate float64) error {
	client.emissions = append(client.emissions, capturedStatsdEmission{kind: "histogram", name: name, value: value, rate: rate, tags: append([]string(nil), tags...)})
	return nil
}

func (client *capturedStatsdClient) Timing(name string, value time.Duration, tags []string, rate float64) error {
	client.emissions = append(client.emissions, capturedStatsdEmission{kind: "timing", name: name, d: value, rate: rate, tags: append([]string(nil), tags...)})
	return nil
}

func newStatsdClientWithFake(t *testing.T, namespace string, options StatsdOptions) (*StatsdMetricsClient, *capturedStatsdClient) {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()

	client, err := NewStatsdMetricsClientWithOptions(listener.LocalAddr().String(), namespace, options)
	require.NoError(t, err)
	realClient := client.statsdClient
	if realClient != nil {
		t.Cleanup(func() { _ = realClient.Close() })
	}
	fake := &capturedStatsdClient{}
	client.statsdClient = fake
	return client, fake
}

func TestStatsdMetricNameOverrides(t *testing.T) {
	tests := []struct {
		name      string
		metric    string
		overrides map[string]MetricNameOverride
		wantNames []string
	}{
		{name: "default", metric: "acl.allow", wantNames: []string{"ns.acl.allow"}},
		{
			name: "replacement", metric: "acl.allow",
			overrides: map[string]MetricNameOverride{"acl.allow": {Name: "custom_acl_allow"}},
			wantNames: []string{"custom_acl_allow"},
		},
		{
			name: "keep original", metric: "acl.allow",
			overrides: map[string]MetricNameOverride{"acl.allow": {Name: "custom_acl_allow", PublishAlongWithOriginal: true}},
			wantNames: []string{"ns.acl.allow", "custom_acl_allow"},
		},
		{
			name: "deduplicate original", metric: "acl.allow",
			overrides: map[string]MetricNameOverride{"acl.allow": {Name: "ns.acl.allow", PublishAlongWithOriginal: true}},
			wantNames: []string{"ns.acl.allow"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, fake := newStatsdClientWithFake(t, "ns.", StatsdOptions{Names: test.overrides})
			require.NoError(t, client.Incr(test.metric, 1))
			require.Len(t, fake.emissions, len(test.wantNames))
			gotNames := make([]string, len(fake.emissions))
			for index, emission := range fake.emissions {
				gotNames[index] = emission.name
			}
			require.Equal(t, test.wantNames, gotNames)
		})
	}
}

func TestStatsdMetricTagsPrecedenceAndRebuild(t *testing.T) {
	client, fake := newStatsdClientWithFake(t, "smokescreen.", StatsdOptions{})
	require.NoError(t, client.AddMetricTags("acl.allow", map[string]string{"team": "payments"}))
	require.NoError(t, client.SetGlobalMetricTags(map[string]string{"env": "prod", "team": "global", "region": "global"}))

	require.NoError(t, client.IncrWithTags("acl.allow", map[string]string{"region": "eu"}, 1))
	require.NoError(t, client.Gauge("requests.concurrent", 7, 1))

	require.Len(t, fake.emissions, 2)
	require.ElementsMatch(t, []string{"env:prod", "region:eu", "team:payments"}, fake.emissions[0].tags)
	require.ElementsMatch(t, []string{"env:prod", "region:global", "team:global"}, fake.emissions[1].tags)

	require.NoError(t, client.SetGlobalMetricTags(map[string]string{"env": "qa", "team": "new-default"}))
	require.NoError(t, client.Incr("acl.allow", 1))
	require.Len(t, fake.emissions, 3)
	require.ElementsMatch(t, []string{"env:qa", "team:payments"}, fake.emissions[2].tags)
}

func TestStatsdMetricNameOverrideInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		override map[string]MetricNameOverride
		wantText string
	}{
		{name: "unknown metric", override: map[string]MetricNameOverride{"not.real": {Name: "custom_name"}}, wantText: "unknown metric"},
		{name: "empty name", override: map[string]MetricNameOverride{"acl.allow": {Name: ""}}, wantText: "cannot be empty"},
		{name: "protocol delimiter", override: map[string]MetricNameOverride{"acl.allow": {Name: "custom|name"}}, wantText: "pipe"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewStatsdMetricsClientWithOptions("", "", StatsdOptions{Names: test.override})
			require.ErrorContains(t, err, test.wantText)
			require.Nil(t, client)
		})
	}
}

func TestStatsdMetricNameOverrideFanoutMethodsAndValues(t *testing.T) {
	tests := []struct {
		name string
		call func(*StatsdMetricsClient) error
		want capturedStatsdEmission
	}{
		{name: "Incr", call: func(client *StatsdMetricsClient) error { return client.Incr("acl.allow", 0.5) }, want: capturedStatsdEmission{kind: "counter", value: 1, rate: 0.5}},
		{name: "IncrWithTags", call: func(client *StatsdMetricsClient) error {
			return client.IncrWithTags("acl.allow", map[string]string{"source": "test"}, 0.75)
		}, want: capturedStatsdEmission{kind: "counter", value: 1, rate: 0.75, tags: []string{"source:test"}}},
		{name: "Gauge", call: func(client *StatsdMetricsClient) error { return client.Gauge("acl.allow", 7, 0.25) }, want: capturedStatsdEmission{kind: "gauge", value: 7, rate: 0.25}},
		{name: "Histogram", call: func(client *StatsdMetricsClient) error { return client.Histogram("acl.allow", 3.5, 0.6) }, want: capturedStatsdEmission{kind: "histogram", value: 3.5, rate: 0.6}},
		{name: "HistogramWithTags", call: func(client *StatsdMetricsClient) error {
			return client.HistogramWithTags("acl.allow", 4.5, map[string]string{"source": "test"}, 0.8)
		}, want: capturedStatsdEmission{kind: "histogram", value: 4.5, rate: 0.8, tags: []string{"source:test"}}},
		{name: "Timing", call: func(client *StatsdMetricsClient) error { return client.Timing("acl.allow", 1500*time.Millisecond, 0.9) }, want: capturedStatsdEmission{kind: "timing", d: 1500 * time.Millisecond, rate: 0.9}},
		{name: "TimingWithTags", call: func(client *StatsdMetricsClient) error {
			return client.TimingWithTags("acl.allow", 2500*time.Millisecond, map[string]string{"source": "test"}, 1)
		}, want: capturedStatsdEmission{kind: "timing", d: 2500 * time.Millisecond, rate: 1, tags: []string{"source:test"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, fake := newStatsdClientWithFake(t, "ns.", StatsdOptions{Names: map[string]MetricNameOverride{
				"acl.allow": {Name: "custom_acl_allow", PublishAlongWithOriginal: true},
			}})

			require.NoError(t, test.call(client))
			require.Len(t, fake.emissions, 2)
			require.Equal(t, []string{"ns.acl.allow", "custom_acl_allow"}, []string{fake.emissions[0].name, fake.emissions[1].name})
			for _, emission := range fake.emissions {
				require.Equal(t, test.want.kind, emission.kind)
				require.Equal(t, test.want.value, emission.value)
				require.Equal(t, test.want.d, emission.d)
				require.Equal(t, test.want.rate, emission.rate)
				require.ElementsMatch(t, test.want.tags, emission.tags)
			}
		})
	}
}
