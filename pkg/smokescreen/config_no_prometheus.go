//go:build smokescreen_no_prometheus

package smokescreen

import "errors"

// SetupPrometheus reports that this binary was built without Prometheus support.
func (config *Config) SetupPrometheus(endpoint string, port string, listenAddr string) error {
	return errors.New("Prometheus support is disabled in this build; run without --expose-prometheus-metrics or rebuild without -tags=smokescreen_no_prometheus")
}
