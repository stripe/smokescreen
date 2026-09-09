//go:build !nounit
// +build !nounit

package smokescreen

import (
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

func TestClearsErrorHeader(t *testing.T) {
	r := require.New(t)

	// For HTTP requests, Smokescreen should ensure successful requests do not include
	// X-Smokescreen-Error, even if they are set by the upstream host.
	t.Run("Clears error header set by upstream", func(t *testing.T) {
		log.SetFlags(log.LstdFlags | log.Lshortfile)

		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		// Create a test http.TestServer to serve a response with the error header set.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(errorHeader, "foobar")
			w.Header().Set("X-Smokescreen-Test", "yes")
			w.WriteHeader(200)
		}))
		defer srv.Close()

		// Talk "through" the proxy to our malicious upstream that sets the
		// error header.
		resp, err := client.Get(srv.URL)
		r.NoError(err)

		// Should succeed
		if resp.StatusCode != 200 {
			t.Errorf("response had bad status: expected 200, got %d", resp.StatusCode)
		}

		// Verify the error header is not set.
		if h := resp.Header.Get(errorHeader); h != "" {
			t.Errorf("proxy did not strip %q header: %q", errorHeader, h)
		}

		// Verify we did get the other header, to confirm we're talking to the right thing
		if h := resp.Header.Get("X-Smokescreen-Test"); h != "yes" {
			t.Errorf("did not get expected header X-Smokescreen-Test: expected \"yes\", got %q", h)
		}
	})

	// Test that the the error header is preserved when a connection is allowed by the ACL,
	// but the connection fails to be established.
	t.Run("Doesn't clear errors for allowed connections", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)

		// Immediately time out to simulate net.Dial timeouts
		cfg.ConnectTimeout = -1

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		resp, err := client.Get("http://127.0.0.1")
		r.NoError(err)

		// Verify the error header is still set
		h := resp.Header.Get(errorHeader)
		if h == "" {
			t.Errorf("proxy stripped %q header: %q", errorHeader, h)
		}
	})
}

func TestConsistentHostHeader(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	hostCh := make(chan string)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
		hostCh <- r.Host
	}))
	defer ts.Close()

	// Custom proxy config for the "remote" httptest.NewServer
	conf := NewConfig()
	conf.ConnTracker = conntrack.NewTracker(conf.IdleTimeout, metrics.NewNoOpMetricsClient(), conf.Log, atomic.Value{}, nil)
	err := conf.SetAllowAddresses([]string{"127.0.0.1"})
	r.NoError(err)

	proxy := BuildProxy(conf)
	proxySrv := httptest.NewServer(proxy)

	client, err := proxyClient(proxySrv.URL)
	r.NoError(err)

	req, err := http.NewRequest("GET", ts.URL, nil)
	r.NoError(err)

	expectedHostHeader := req.Host
	go client.Do(req)

	select {
	case receivedHostHeader := <-hostCh:
		a.Equal(expectedHostHeader, receivedHostHeader)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for client request")
	}
}

func TestClearsTraceIDHeader(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	headerCh := make(chan string)
	respCh := make(chan bool)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
		headerCh <- r.Header.Get("X-Smokescreen-Trace-ID")
	}))
	defer ts.Close()

	// Custom proxy config for the "remote" httptest.NewServer
	var logHook logrustest.Hook
	conf := NewConfig()
	conf.Log.AddHook(&logHook)
	conf.ConnTracker = conntrack.NewTracker(conf.IdleTimeout, metrics.NewNoOpMetricsClient(), conf.Log, atomic.Value{}, nil)
	err := conf.SetAllowAddresses([]string{"127.0.0.1"})
	r.NoError(err)

	proxy := BuildProxy(conf)
	proxySrv := httptest.NewServer(proxy)

	client, err := proxyClient(proxySrv.URL)
	r.NoError(err)

	req, err := http.NewRequest("GET", ts.URL, nil)
	r.NoError(err)
	req.Header.Set("X-Smokescreen-Trace-ID", "6c4aa514e3da13ef")

	go func() {
		client.Do(req)
		respCh <- true
	}()

	select {
	case receivedTraceIDCh := <-headerCh:
		a.Empty(receivedTraceIDCh)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for client request")
	}

	select {
	case <-respCh:
		entry := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(entry)
		a.NotEmpty(entry.Data["trace_id"])
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server response")
	}

}
