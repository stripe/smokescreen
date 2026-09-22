//go:build smokescreen_no_prometheus

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfigurationWithoutPrometheus(t *testing.T) {
	conf, err := NewConfiguration([]string{"smokescreen"}, nil)

	require.NoError(t, err)
	require.NotNil(t, conf)
}

func TestNewConfigurationRejectsPrometheusWhenDisabled(t *testing.T) {
	conf, err := NewConfiguration([]string{"smokescreen", "--expose-prometheus-metrics"}, nil)

	require.Nil(t, conf)
	require.EqualError(t, err, "Prometheus support is disabled in this build; run without --expose-prometheus-metrics or rebuild without -tags=smokescreen_no_prometheus")
}
