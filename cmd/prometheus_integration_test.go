//go:build integration && !smokescreen_no_prometheus

package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPrometheusMetricsEndpoint(t *testing.T) {
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	metricsPort := strconv.Itoa(metricsListener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, metricsListener.Close())

	endpoint := "/metrics-integration"
	args := []string{
		"smokescreen",
		"--listen-ip=127.0.0.1",
		"--egress-acl-file=testdata/sample_config.yaml",
		"--expose-prometheus-metrics",
		fmt.Sprintf("--prometheus-endpoint=%s", endpoint),
		"--prometheus-listen-ip=127.0.0.1",
		fmt.Sprintf("--prometheus-port=%s", metricsPort),
	}

	_, err = NewConfiguration(args, nil)
	require.NoError(t, err)

	metricsURL := fmt.Sprintf("http://127.0.0.1:%s%s", metricsPort, endpoint)
	metricsClient := &http.Client{Transport: &http.Transport{Proxy: nil}}
	require.Eventually(t, func() bool {
		resp, err := metricsClient.Get(metricsURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}

		body, err := io.ReadAll(resp.Body)
		return err == nil && strings.Contains(string(body), "go_gc_duration_seconds")
	}, time.Second, 10*time.Millisecond)
}
