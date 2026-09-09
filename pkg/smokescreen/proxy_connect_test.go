//go:build !nounit
// +build !nounit

package smokescreen

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

var invalidHostCases = []struct {
	scheme    string
	proxyType string
}{
	{"http", "http"},
	{"https", "connect"},
}

func TestInvalidHost(t *testing.T) {
	for _, testCase := range invalidHostCases {
		t.Run(testCase.scheme, func(t *testing.T) {
			a := assert.New(t)
			r := require.New(t)

			cfg, err := testConfig("test-trusted-srv")
			require.NoError(t, err)
			logHook := proxyLogHook(cfg)

			proxySrv := proxyServer(cfg)
			defer proxySrv.Close()

			// Create a http.Client that uses our proxy
			client, err := proxyClient(proxySrv.URL)
			r.NoError(err)

			// This hostname does not exist and should never resolve
			resp, err := client.Get(fmt.Sprintf("%s://notarealhost.test", testCase.scheme))
			if testCase.scheme == "https" {
				r.Error(err)
				r.Contains(err.Error(), "Bad gateway")
			} else {
				// Plain HTTP
				r.NoError(err)
				r.Equal(http.StatusBadGateway, resp.StatusCode)

				defer resp.Body.Close()
				b, _ := ioutil.ReadAll(resp.Body)
				r.Contains(string(b), "Failed to resolve remote hostname")
			}

			entry := findCanonicalProxyDecision(logHook.AllEntries())
			r.NotNil(entry)

			if a.Contains(entry.Data, "allow") {
				a.Equal(true, entry.Data["allow"])
			}
			if a.Contains(entry.Data, "error") {
				a.Contains(entry.Data["error"], "no such host")
			}
			if a.Contains(entry.Data, "proxy_type") {
				a.Contains(entry.Data["proxy_type"], testCase.proxyType)
			}
		})
	}
}

func TestErrorHeader(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	cfg, err := testConfig("test-trusted-srv")
	require.NoError(t, err)
	logHook := proxyLogHook(cfg)

	proxySrv := proxyServer(cfg)
	defer proxySrv.Close()

	// Create a http.Client that uses our proxy
	client, err := proxyClient(proxySrv.URL)
	r.NoError(err)

	resp, err := client.Get("http://example.com")
	r.NoError(err)
	r.Equal(http.StatusProxyAuthRequired, resp.StatusCode)
	r.NotEmpty(resp.Header.Get("X-Smokescreen-Error"))

	entry := findCanonicalProxyDecision(logHook.AllEntries())
	r.NotNil(entry)

	if a.Contains(entry.Data, "allow") {
		a.Equal(false, entry.Data["allow"])
	}
}

// TestProxyProtocols ensures that both traditional HTTP and CONNECT proxy
// requests Emit the correct CANONICAL-PROXY-DECISION log
func TestProxyProtocols(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)
	t.Run("HTTP proxy", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		clientCh := make(chan bool)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		logHook := proxyLogHook(cfg)
		proxy := proxyServer(cfg)
		remote := httptest.NewServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		go func() {
			client.Do(req)
			clientCh <- true
		}()
		<-clientCh

		// Metrics should show one successful connection and a corresponding successful
		// DNS request along with its timing metric.
		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "true"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		lookups, err := tmc.GetCount("resolver.attempts_total", make(map[string]string))
		r.NoError(err)
		r.Equal(lookups, uint64(1))
		ltime, err := tmc.GetCount("resolver.lookup_time", make(map[string]string))
		r.NoError(err)
		r.Equal(ltime, uint64(1))

		entry := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(entry)

		r.Contains(entry.Data, "proxy_type")
		r.Equal("http", entry.Data["proxy_type"])
	})

	t.Run("CONNECT proxy", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		clientCh := make(chan bool)
		serverCh := make(chan bool)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverCh <- true
			<-serverCh
			w.Write([]byte("OK"))
		})

		logHook := proxyLogHook(cfg)
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		go func() {
			client.Do(req)
			clientCh <- true
		}()

		<-serverCh
		count := 0
		cfg.ConnTracker.Range(func(k, v interface{}) bool {
			count++
			return true
		})
		a.Equal(1, count, "connTracker should contain one tracked connection")

		serverCh <- true
		<-clientCh

		// Metrics should show one successful connection and a corresponding successful
		// DNS request along with its timing metric.
		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "true"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		lookups, err := tmc.GetCount("resolver.attempts_total", make(map[string]string))
		r.NoError(err)
		r.Equal(lookups, uint64(1))
		ltime, err := tmc.GetCount("resolver.lookup_time", make(map[string]string))
		r.NoError(err)
		r.Equal(ltime, uint64(1))

		entry := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(entry)
		r.Contains(entry.Data, "proxy_type")
		r.Equal("connect", entry.Data["proxy_type"])
	})
}

func TestProxyTimeouts(t *testing.T) {
	r := require.New(t)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.Write([]byte("OK"))
	})

	t.Run("HTTP proxy timeouts", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		logHook := proxyLogHook(cfg)
		cfg.IdleTimeout = 100 * time.Millisecond

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		resp, _ := client.Do(req)
		r.Equal(http.StatusGatewayTimeout, resp.StatusCode)
		r.NotEqual("", resp.Header.Get(errorHeader))

		entry := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(entry)

		r.Equal("http", entry.Data["proxy_type"])
		r.Contains(entry.Data["error"], "i/o timeout")
		r.Equal(entry.Data["status_code"], 504)
	})

	// This isn't quite correct, as there is some nondeterministic behavior with the way
	// CONNECT timeout errors are surfaced back to Smokescreen from Goproxy. We check
	// for an EOF returned from HTTP client to indicate a connection interruption
	// which in our case represents the timeout.
	//
	// To correctly hook into this, we'd need to pass a Logger from Smokescreen to Goproxy
	// which we have hooks into. This would be able to verify the timeout as errors from
	// each end of the connection pair are logged by Goproxy.
	t.Run("CONNECT proxy timeouts", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		logHook := proxyLogHook(cfg)
		cfg.IdleTimeout = 100 * time.Millisecond

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		resp, err := client.Do(req)
		r.Nil(resp)
		r.Error(err)
		r.Contains(err.Error(), "EOF")

		cfg.ConnTracker.Wg().Wait()

		// The metrics client records success:true because of the way Goproxy surfaces CONNECT
		// timeouts to Smokescreen; same reasons we test for EOF above.
		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "true"})
		r.NoError(err)
		r.Equal(i, uint64(1))

		entry := findCanonicalProxyClose(logHook.AllEntries())
		r.NotNil(entry)
	})

	t.Run("CONNECT proxy dial timeouts", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		cfg.ConnectTimeout = -1

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		// Go swallows the response as the CONNECT tunnel was never established
		resp, err := client.Do(req)
		r.Nil(resp)
		r.Error(err)
		r.Contains(err.Error(), "Gateway timeout")

		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "false"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		i, err = tmc.GetCount("cn.atpt.connect.err", map[string]string{"type": "timeout"})
		r.NoError(err)
		r.Equal(i, uint64(1))
	})

	t.Run("HTTP proxy dial timeouts", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		cfg.ConnectTimeout = -1

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		resp, _ := client.Do(req)
		r.Equal(http.StatusGatewayTimeout, resp.StatusCode)
		r.NotEqual("", resp.Header.Get(errorHeader))
	})
}

// TestProxyConnectFailure tests that the proxy correctly handles non-timeout connection failures.
// In general, the proxy should respond with "Bad gateway" and record failure statistics
// reflecting the cause of the failure.
func TestProxyConnectFailure(t *testing.T) {
	r := require.New(t)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.Write([]byte("OK"))
	})

	t.Run("CONNECT proxy dial refused", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		// Don't time out immediately
		cfg.ConnectTimeout = time.Minute

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		// Shut down the handler so that the proxy won't be able to connect at all
		remote.Close()

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)
		resp, err := client.Do(req)
		r.Nil(resp)
		r.Error(err)
		r.Contains(err.Error(), "Bad gateway")

		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "false"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		i, err = tmc.GetCount("cn.atpt.connect.err", map[string]string{"type": "refused"})
		r.NoError(err)
		r.Equal(i, uint64(1))
	})
}

// TestProxyHalfClosed tests that the proxy and proxy client correctly
// closes all connections if the proxy target attempts to half-close
// the TCP connection.
func TestProxyHalfClosed(t *testing.T) {
	r := require.New(t)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("couldn't hijack conn")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Error(err)
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			t.Error("conn did not unwrap to tls.Conn")
		}

		// Send a response
		if _, err := io.WriteString(bufrw, "HTTP/1.1 200 TCP is great!\r\n\r\n"); err != nil {
			t.Errorf("Error responding to client: %s", err)
		}
		bufrw.Flush()
		tlsConn.CloseWrite()
	})

	cfg, err := testConfig("test-local-srv")
	r.NoError(err)
	err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
	r.NoError(err)

	logHook := proxyLogHook(cfg)

	l, err := net.Listen("tcp", "localhost:0")
	r.NoError(err)
	cfg.Listener = l

	proxy := proxyServer(cfg)
	remote := httptest.NewTLSServer(h)
	client, err := proxyClient(proxy.URL)
	r.NoError(err)

	req, err := http.NewRequest("GET", remote.URL, nil)
	r.NoError(err)

	resp, err := client.Do(req)
	r.NoError(err)
	resp.Body.Close()
	r.Equal(http.StatusOK, resp.StatusCode)

	cfg.ConnTracker.Wg().Wait()

	tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
	r.True(ok)
	i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "true"})
	r.NoError(err)
	r.Equal(i, uint64(1))

	entry := findCanonicalProxyClose(logHook.AllEntries())
	r.NotNil(entry)
}

func TestCustomDialTimeout(t *testing.T) {
	r := require.New(t)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.Write([]byte("OK\n"))
	})

	t.Run("CONNECT proxy custom dial timeouts", func(t *testing.T) {
		var custom = false
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		cfg.ConnectTimeout = -1

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l
		cfg.ProxyDialTimeout = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
			custom = true
			return net.DialTimeout(network, address, timeout)
		}

		proxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		// Go swallows the response as the CONNECT tunnel was never established
		resp, err := client.Do(req)
		r.Nil(resp)
		r.Error(err)
		r.Contains(err.Error(), "Gateway timeout")
		r.Equal(custom, true)

		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "false"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		i, err = tmc.GetCount("cn.atpt.connect.err", map[string]string{"type": "timeout"})
		r.NoError(err)
		r.Equal(i, uint64(1))
	})

	t.Run("HTTP proxy custom dial timeouts", func(t *testing.T) {
		var custom = false
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		cfg.ConnectTimeout = -1

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		cfg.ProxyDialTimeout = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
			custom = true
			return net.DialTimeout(network, address, timeout)
		}

		proxy := proxyServer(cfg)
		remote := httptest.NewServer(h)
		client, err := proxyClient(proxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		resp, _ := client.Do(req)
		r.Equal(http.StatusGatewayTimeout, resp.StatusCode)
		r.NotEqual("", resp.Header.Get(errorHeader))

		r.Equal(custom, true)

		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "false"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		i, err = tmc.GetCount("cn.atpt.connect.err", map[string]string{"type": "timeout"})
		r.NoError(err)
		r.Equal(i, uint64(1))

	})
}

// Test that Smokescreen calls the custom reject response handler (if defined in the Config struct)
// after every denied request
