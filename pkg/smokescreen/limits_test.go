//go:build !nounit
// +build !nounit

package smokescreen

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMaxConcurrentConnectTunnels(t *testing.T) {
	// Create a slow backend that holds connections open
	slowBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Hold the connection open for a bit
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer slowBackend.Close()

	t.Run("tunnel limit enforced", func(t *testing.T) {
		r := require.New(t)
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		// Set tunnel limit to 2
		cfg.MaxConcurrentConnectTunnels = 2
		cfg.TunnelLimiter = NewTunnelLimiter(2, cfg)

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxySrv := proxyServer(cfg)
		defer proxySrv.Close()

		// Track results
		var successCount, rejectCount int32
		var wg sync.WaitGroup

		// Try to open 5 concurrent CONNECT tunnels
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				client, err := proxyClient(proxySrv.URL)
				if err != nil {
					t.Logf("Failed to create client: %v", err)
					return
				}
				client.Timeout = 2 * time.Second

				resp, err := client.Get(slowBackend.URL)
				if err != nil {
					// Check if it's a tunnel limit error or rejection
					if strings.Contains(err.Error(), "Too Many Requests") ||
						strings.Contains(err.Error(), "maximum concurrent connect tunnels") ||
						strings.Contains(err.Error(), "Request rejected by proxy") {
						atomic.AddInt32(&rejectCount, 1)
					} else {
						t.Logf("Request error: %v", err)
					}
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					atomic.AddInt32(&successCount, 1)
				} else if resp.StatusCode == 429 || resp.StatusCode == 407 {
					atomic.AddInt32(&rejectCount, 1)
				}
			}()
		}

		wg.Wait()

		// With limit of 2, we expect at most 2 successes
		// Some requests should be rejected
		t.Logf("Success: %d, Rejected: %d", successCount, rejectCount)
		r.LessOrEqual(int(successCount), 2, "Should not exceed tunnel limit")
		r.Greater(int(rejectCount), 0, "Some requests should be rejected")
	})

	t.Run("tunnel slots released on close", func(t *testing.T) {
		r := require.New(t)
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		// Set tunnel limit to 1
		cfg.MaxConcurrentConnectTunnels = 1
		cfg.TunnelLimiter = NewTunnelLimiter(1, cfg)

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxySrv := proxyServer(cfg)
		defer proxySrv.Close()

		// Quick backend that responds immediately
		quickBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		}))
		defer quickBackend.Close()

		// Make sequential requests - they should all succeed because
		// each one completes before the next starts
		for i := 0; i < 3; i++ {
			client, err := proxyClient(proxySrv.URL)
			r.NoError(err)
			client.Timeout = 5 * time.Second

			resp, err := client.Get(quickBackend.URL)
			r.NoError(err, "Request %d should succeed", i)
			resp.Body.Close()
			r.Equal(200, resp.StatusCode, "Request %d should return 200", i)

			// Go 1.27 may keep the CONNECT tunnel alive after closing the response
			// body; close idle connections before waiting for the proxy connection
			// tracker. See https://github.com/golang/go/issues/77370.
			client.CloseIdleConnections()
			cfg.ConnTracker.Wg().Wait()
		}
	})

	t.Run("zero limit means unlimited", func(t *testing.T) {
		r := require.New(t)
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		// Set tunnel limit to 0 (unlimited)
		cfg.MaxConcurrentConnectTunnels = 0
		cfg.TunnelLimiter = nil // No limiter when unlimited

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxySrv := proxyServer(cfg)
		defer proxySrv.Close()

		// Quick backend
		quickBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		}))
		defer quickBackend.Close()

		// Should be able to make many requests
		for i := 0; i < 5; i++ {
			client, err := proxyClient(proxySrv.URL)
			r.NoError(err)

			resp, err := client.Get(quickBackend.URL)
			r.NoError(err, "Request %d should succeed with no limit", i)
			resp.Body.Close()
			r.Equal(200, resp.StatusCode)
		}
	})
}
