//go:build !nounit
// +build !nounit

package smokescreen

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

var allowRanges = []string{
	"8.8.9.0/24",
	"10.0.1.0/24",
	"172.16.1.0/24",
	"192.168.1.0/24",
	"127.0.1.0/24",
}
var allowAddresses = []string{
	"10.0.0.1:321",
}
var denyRanges = []string{
	"1.1.1.1/32",
}
var denyAddresses = []string{
	"8.8.8.8:321",
}

type testCase struct {
	ip       string
	port     int
	expected ipType
}

func TestClassifyAddr(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	a.NoError(conf.SetDenyRanges(denyRanges))
	a.NoError(conf.SetDenyAddresses(denyAddresses))
	a.NoError(conf.SetAllowRanges(allowRanges))
	a.NoError(conf.SetAllowAddresses(allowAddresses))
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"

	testIPs := []testCase{
		testCase{"8.8.8.8", 1, ipAllowDefault},
		testCase{"8.8.9.8", 1, ipAllowUserConfigured},

		// Specific blocked networks
		testCase{"10.0.0.1", 1, ipDenyPrivateRange},
		testCase{"10.0.0.1", 321, ipAllowUserConfigured},
		testCase{"10.0.1.1", 1, ipAllowUserConfigured},
		testCase{"172.16.0.1", 1, ipDenyPrivateRange},
		testCase{"172.16.1.1", 1, ipAllowUserConfigured},
		testCase{"192.168.0.1", 1, ipDenyPrivateRange},
		testCase{"192.168.1.1", 1, ipAllowUserConfigured},
		testCase{"8.8.8.8", 321, ipDenyUserConfigured},
		testCase{"1.1.1.1", 1, ipDenyUserConfigured},

		// localhost
		testCase{"127.0.0.1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"::1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.0.1.1", 1, ipAllowUserConfigured},

		// ec2 metadata endpoint
		testCase{"169.254.169.254", 1, ipDenyNotGlobalUnicast},

		// Broadcast addresses
		testCase{"255.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"ff02:0:0:0:0:0:0:2", 1, ipDenyNotGlobalUnicast},
	}

	for _, test := range testIPs {
		localIP := net.ParseIP(test.ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", test.ip)
			continue
		}
		localAddr := net.TCPAddr{
			IP:   localIP,
			Port: test.port,
		}

		got := classifyAddr(conf, &localAddr)
		if got != test.expected {
			t.Errorf("Misclassified IP (%s): should be %s, but is instead %s.", localIP, test.expected, got)
		}
	}
}

func TestUnsafeAllowPrivateRanges(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	a.NoError(conf.SetDenyRanges([]string{"192.168.0.0/24", "10.0.0.0/8"}))
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"

	conf.UnsafeAllowPrivateRanges = true

	testIPs := []testCase{
		testCase{"8.8.8.8", 1, ipAllowDefault},

		// Specific blocked networks
		testCase{"10.0.0.1", 1, ipDenyUserConfigured},
		testCase{"10.0.0.1", 321, ipDenyUserConfigured},
		testCase{"10.0.1.1", 1, ipDenyUserConfigured},
		testCase{"172.16.0.1", 1, ipAllowDefault},
		testCase{"172.16.1.1", 1, ipAllowDefault},
		testCase{"192.168.0.1", 1, ipDenyUserConfigured},
		testCase{"192.168.1.1", 1, ipAllowDefault},

		// localhost
		testCase{"127.0.0.1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"::1", 1, ipDenyNotGlobalUnicast},

		// ec2 metadata endpoint
		testCase{"169.254.169.254", 1, ipDenyNotGlobalUnicast},

		// Broadcast addresses
		testCase{"255.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"ff02:0:0:0:0:0:0:2", 1, ipDenyNotGlobalUnicast},
	}

	for _, test := range testIPs {
		localIP := net.ParseIP(test.ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", test.ip)
			continue
		}
		localAddr := net.TCPAddr{
			IP:   localIP,
			Port: test.port,
		}

		got := classifyAddr(conf, &localAddr)
		if got != test.expected {
			t.Errorf("Misclassified IP (%s): should be %s, but is instead %s.", localIP, test.expected, got)
		}
	}

}

// TestClearsErrors tests that we are correctly preserving/removing the X-Smokescreen-Error header.
// This header is used to provide more granular errors to proxy clients, and signals that
// there was an issue connecting to the proxy target.
func TestClearsErrorHeader(t *testing.T) {
	r := require.New(t)

	// For HTTP requests, Smokescreen should ensure successful requests do not include
	// X-Smokescreen-Error, even if they are set by the upstream host.
	t.Run("Clears error header set by upstream", func(t *testing.T) {
		log.SetFlags(log.LstdFlags | log.Lshortfile)

		cfg, err := testConfig("test-trusted-srv")
		r.NoError(err)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		// Talk "through" the proxy to our malicious upstream that sets the
		// error header.
		resp, err := client.Get("http://httpbin.org/response-headers?X-Smokescreen-Error=foobar&X-Smokescreen-Test=yes")
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

func TestShuttingDownValue(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	conf.Port = 39381

	quit := make(chan interface{})
	go StartWithConfig(conf, quit)

	// These sleeps are not ideal, but there is a race with checking the
	// ShuttingDown value from these tests. The server has to bootstrap
	// itself with an initial value before it returns false, and has to
	// set the value to true after we send on the quit channel.
	time.Sleep(500 * time.Millisecond)
	a.Equal(false, conf.ShuttingDown.Load())

	quit <- true

	time.Sleep(500 * time.Millisecond)
	a.Equal(true, conf.ShuttingDown.Load())

}

func TestHealthcheck(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	healthcheckCh := make(chan string)

	testHealthcheck := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
		healthcheckCh <- "OK"
	})

	conf := NewConfig()

	// We set this here so that we can deterministically test the Healthcheck
	// handler. Otherwise we would have to call StartWithConfig() in a goroutine,
	// which creates a race between the test and the listener accepting
	// connections.
	handler := HealthcheckMiddleware{
		Proxy:       BuildProxy(conf),
		Healthcheck: testHealthcheck,
	}

	server := httptest.NewServer(handler)

	errChan := make(chan error, 1)
	go func() {
		select {
		case healthy := <-healthcheckCh:
			if healthy != "OK" {
				errChan <- fmt.Errorf("healthcheck not OK: %s", healthy)
			}
		case <-time.After(5 * time.Second):
			errChan <- errors.New("timed out waiting for client request")
		}
		close(errChan)
	}()

	resp, err := http.Get(fmt.Sprintf("%s/healthcheck", server.URL))
	r.NoError(err)
	a.Equal(http.StatusOK, resp.StatusCode)

	r.NoError(<-errChan)
}

var invalidHostCases = []struct {
	scheme    string
	expectErr bool
	proxyType string
}{
	{"http", false, "http"},
	{"https", true, "connect"},
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

			resp, err := client.Get(fmt.Sprintf("%s://notarealhost.test", testCase.scheme))
			if testCase.expectErr {
				r.Contains(err.Error(), "Request rejected by proxy")
			} else {
				r.NoError(err)
				r.Equal(http.StatusBadGateway, resp.StatusCode)
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

var hostSquareBracketsCases = []struct {
	scheme    string
	proxyType string
	hostname  string
	msg       string
}{
	{"http", "http", "[stripe.com]", "invalid domain \"[stripe.com]\": disallowed rune U+005B"},
	{"https", "connect", "[stripe.com]", "host matched rule in global deny list"},
	{"http", "http", "[[stripe.com]]", "invalid domain \"[[stripe.com]]\": disallowed rune U+005B"},
	{"https", "connect", "[[stripe.com]]", "host matched rule in global deny list"},
	{"http", "http", "[[[stripe.com]]]", "invalid domain \"[[[stripe.com]]]\": disallowed rune U+005B"},
	{"https", "connect", "[2001:Db8::]:443", "Destination host cannot be determined"},
	// These somewhat confusing error messages originate from net.SplitHostPort().
	{"https", "connect", "[[[stripe.com]]]", "address [[stripe.com]]:443: missing port in address"},
	{"http", "http", "[[stripe.com]]:80", "address [[stripe.com]]:80: missing port in address"},
}

func TestHostSquareBrackets(t *testing.T) {
	for _, testCase := range hostSquareBracketsCases {
		t.Run(testCase.scheme+"://"+testCase.hostname, func(t *testing.T) {
			r := require.New(t)

			cfg, err := testConfig("test-open-srv")
			require.NoError(t, err)
			logHook := proxyLogHook(cfg)

			proxySrv := proxyServer(cfg)
			defer proxySrv.Close()

			// Create a http.Client that uses our proxy
			client, err := proxyClient(proxySrv.URL)
			r.NoError(err)

			resp, err := client.Get(fmt.Sprintf("%s://%s", testCase.scheme, testCase.hostname))
			if err != nil {
				r.Contains(err.Error(), "Request rejected by proxy")
			} else {
				r.Equal(http.StatusProxyAuthRequired, resp.StatusCode)
			}

			entry := findCanonicalProxyDecision(logHook.AllEntries())
			r.NotNil(entry)

			r.Equal(entry.Data["proxy_type"], testCase.proxyType)
			if allowed, ok := entry.Data["allow"]; ok {
				r.Equal(false, allowed)
				r.Equal(testCase.msg, entry.Data["decision_reason"])
			} else {
				r.Equal(testCase.msg, entry.Data["error"])
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
		i, err := tmc.GetCount("cn.atpt.total", "success:true")
		r.NoError(err)
		r.Equal(i, uint64(1))
		lookups, err := tmc.GetCount("resolver.attempts_total")
		r.NoError(err)
		r.Equal(lookups, uint64(1))
		ltime, err := tmc.GetCount("resolver.lookup_time")
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
		i, err := tmc.GetCount("cn.atpt.total", "success:true")
		r.NoError(err)
		r.Equal(i, uint64(1))
		lookups, err := tmc.GetCount("resolver.attempts_total")
		r.NoError(err)
		r.Equal(lookups, uint64(1))
		ltime, err := tmc.GetCount("resolver.lookup_time")
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
	})

	// This isn't quite correct, as there is some nondeterministic behavior with the way
	// CONNECT timeout errors are surfaced back to Smokescreen from Goproxy. We check
	// for an EOF returned from HTTP client to indicate a connection interruption
	// which in our case represents the timeout.
	//
	// To correctly hook into this, we'd need to pass a logger from Smokescreen to Goproxy
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
func TestRejectResponseHandler(t *testing.T) {
	r := require.New(t)
	testHeader := "TestRejectResponseHandlerHeader"
	t.Run("Testing custom reject response handler", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")

		// set a custom RejectResponseHandler that will set a header on every reject response
		cfg.RejectResponseHandler = func(resp *http.Response) {
			resp.Header.Set(testHeader, "This header is added by the RejectResponseHandler")
		}
		r.NoError(err)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		// Send a request that should be blocked
		resp, err := client.Get("http://127.0.0.1")
		r.NoError(err)

		// The RejectResponseHandler should set our custom header
		h := resp.Header.Get(testHeader)
		if h == "" {
			t.Errorf("Expecting header %s to be set by RejectResponseHandler", testHeader)
		}
		// Send a request that should be allowed
		resp, err = client.Get("http://example.com")
		r.NoError(err)

		// The header set by our custom reject response handler should not be set
		h = resp.Header.Get(testHeader)
		if h != "" {
			t.Errorf("Expecting header %s to not be set by RejectResponseHandler", testHeader)
		}
	})
}

func TestCustomRequestHandler(t *testing.T) {
	r := require.New(t)
	testHeader := "X-Verify-Request-Header"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(testHeader) != "" {
			w.Write([]byte("header not removed!"))
			return
		}
		w.Write([]byte("OK"))
	})
	customRequestHandler := func(r *http.Request) error {
		header := r.Header.Get(testHeader)
		r.Header.Del(testHeader)
		if header == "" {
			return errors.New("header doesn't exist")
		}
		if header != "valid" {
			return errors.New("invalid header")
		}
		return nil
	}

	t.Run("CustomRequestHandler works for HTTPS", func(t *testing.T) {
		testCases := []struct {
			header        http.Header
			expectedError bool
		}{
			{
				header:        http.Header{testHeader: []string{"valid"}},
				expectedError: false,
			},
			{
				header:        http.Header{testHeader: []string{"invalid"}},
				expectedError: true,
			},
		}
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)
		cfg.CustomRequestHandler = customRequestHandler

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)
		defer proxy.Close()
		for _, testCase := range testCases {

			client, err := proxyClientWithConnectHeaders(proxy.URL, testCase.header)
			r.NoError(err)

			req, err := http.NewRequest("GET", remote.URL, nil)
			r.NoError(err)
			resp, err := client.Do(req)
			if testCase.expectedError {
				r.Nil(resp)
				r.Contains(err.Error(), "Request rejected by proxy")
			} else {
				r.NoError(err)
				r.Equal(200, resp.StatusCode)
				body, err := ioutil.ReadAll(resp.Body)
				r.NoError(err)
				resp.Body.Close()
				r.Equal([]byte("OK"), body)
			}
		}
	})

	t.Run("CustomRequestHandler works for HTTP", func(t *testing.T) {
		testCases := []struct {
			header        string
			expectedError bool
		}{
			{
				header:        "valid",
				expectedError: false,
			},
			{
				header:        "invalid",
				expectedError: true,
			},
		}
		cfg, err := testConfig("test-local-srv")
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)
		cfg.CustomRequestHandler = customRequestHandler

		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		remote := httptest.NewServer(h)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		for _, testCase := range testCases {
			req, err := http.NewRequest("GET", remote.URL, nil)
			r.NoError(err)
			req.Header.Set(testHeader, testCase.header)
			resp, err := client.Do(req)
			if testCase.expectedError {
				r.NoError(err)
				errorMessage := resp.Header.Get("X-Smokescreen-Error")
				r.Contains(errorMessage, "invalid header")

			} else {
				r.NoError(err)
				r.Equal(200, resp.StatusCode)
				body, err := ioutil.ReadAll(resp.Body)
				r.NoError(err)
				resp.Body.Close()
				r.Equal([]byte("OK"), body)

			}
		}
	})
}

func findCanonicalProxyDecision(logs []*logrus.Entry) *logrus.Entry {
	for _, entry := range logs {
		if entry.Message == CanonicalProxyDecision {
			return entry
		}
	}
	return nil
}

func findCanonicalProxyClose(logs []*logrus.Entry) *logrus.Entry {
	for _, entry := range logs {
		if entry.Message == conntrack.CanonicalProxyConnClose {
			return entry
		}
	}
	return nil
}

func testConfig(role string) (*Config, error) {
	conf := NewConfig()

	if err := conf.SetAllowRanges(allowRanges); err != nil {
		return nil, err
	}
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"
	conf.Resolver = &net.Resolver{}
	conf.SetupEgressAcl("testdata/acl.yaml")
	conf.RoleFromRequest = func(req *http.Request) (string, error) {
		return role, nil
	}

	mc := metrics.NewMockMetricsClient()
	conf.ConnTracker = conntrack.NewTracker(conf.IdleTimeout, mc, conf.Log, atomic.Value{}, nil)
	conf.MetricsClient = mc
	return conf, nil
}

func proxyLogHook(conf *Config) *logrustest.Hook {
	var testHook logrustest.Hook
	conf.Log.AddHook(&testHook)
	return &testHook
}

func proxyServer(conf *Config) *httptest.Server {
	proxy := BuildProxy(conf)
	return httptest.NewServer(proxy)
}

func proxyClient(proxy string) (*http.Client, error) {
	return proxyClientWithConnectHeaders(proxy, nil)
}

func proxyClientWithConnectHeaders(proxy string, proxyConnectHeaders http.Header) (*http.Client, error) {
	proxyUrl, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyUrl),
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ProxyConnectHeader:    proxyConnectHeaders,
		},
	}, nil
}
