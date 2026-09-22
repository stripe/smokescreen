package smokescreen

import (
	"io"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
 "github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

// Keep HTTP connections and CONNECT tunnels pooled, as real clients do. Each
// worker retains its own latency samples and merges them once outside its loop.
func BenchmarkProxyTraffic(b *testing.B) {
	for _, protocol := range []string{"HTTP", "CONNECT"} {
		b.Run(protocol, func(b *testing.B) {
			cfg, err := testConfig("test-local-srv")
			require.NoError(b, err)
			cfg.Log.SetOutput(io.Discard)
 cfg.Log.SetFormatter(&logrus.JSONFormatter{})
 cfg.MetricsClient = metrics.NewNoOpMetricsClient()
			require.NoError(b, cfg.SetAllowAddresses([]string{"127.0.0.1"}))
			cfg.TransportMaxIdleConns = 256
 cfg.TransportMaxIdleConnsPerHost = 128
 proxy := BuildProxy(cfg)
			server := httptest.NewServer(proxy)
			defer server.Close()
			defer proxy.Tr.CloseIdleConnections()
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
			var origin *httptest.Server
			if protocol == "CONNECT" { origin = httptest.NewTLSServer(handler) } else { origin = httptest.NewServer(handler) }
			defer origin.Close()
			client, err := proxyClient(server.URL)
			require.NoError(b, err)
			client.Transport.(*http.Transport).MaxIdleConnsPerHost = 128
			defer client.CloseIdleConnections()
			var mu sync.Mutex
			var samples []int64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				var local []int64
				for pb.Next() {
					start := time.Now()
					resp, err := client.Get(origin.URL)
					if err != nil { b.Error(err); return }
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					local = append(local, time.Since(start).Nanoseconds())
					if resp.StatusCode != http.StatusOK { b.Error(resp.Status) }
				}
				mu.Lock()
				samples = append(samples, local...)
				mu.Unlock()
			})
			b.StopTimer()
			sort.Slice(samples, func(i,j int) bool { return samples[i] < samples[j] })
			if len(samples)>0 {
				b.ReportMetric(float64(samples[len(samples)/2]), "p50-ns/request")
				b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns/request")
			}
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "requests/s")
		})
	}
}
