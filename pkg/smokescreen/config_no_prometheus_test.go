//go:build smokescreen_no_prometheus

package smokescreen

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupPrometheusIsDisabled(t *testing.T) {
	err := NewConfig().SetupPrometheus(DefaultPrometheusEndpoint, DefaultPrometheusPort, DefaultPrometheusListenIP)

	require.EqualError(t, err, "Prometheus support is disabled in this build; run without --expose-prometheus-metrics or rebuild without -tags=smokescreen_no_prometheus")
}
