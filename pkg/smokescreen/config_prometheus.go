//go:build !smokescreen_no_prometheus

package smokescreen

import "github.com/stripe/smokescreen/v2/pkg/smokescreen/metrics"

func (config *Config) SetupPrometheus(endpoint string, port string, listenAddr string, formats ...string) error {
	metricsClient, err := metrics.NewPrometheusMetricsClient(endpoint, port, listenAddr, formats...)
	if err != nil {
		return err
	}
	config.MetricsClient = metricsClient
	return nil
}
