//go:build !nounit
// +build !nounit

package smokescreen

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCONNECTProxyACLs(t *testing.T) {
	t.Run("Blocks a non-approved proxy when the X-Upstream-Https-Proxy header is set", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})
		r := require.New(t)
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg, err := testConfig("test-external-connect-proxy-blocked-srv")
		r.NoError(err)
		cfg.Listener = l

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		internalToStripeProxy := proxyServer(cfg)
		logHook := proxyLogHook(cfg)
		remote := httptest.NewTLSServer(h)

		client, err := proxyClientWithConnectHeaders(internalToStripeProxy.URL, http.Header{"X-Upstream-Https-Proxy": []string{"https://google.com"}})
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		client.Do(req)

		entry := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(entry)
		r.Equal("connect proxy host not allowed in rule", entry.Data["decision_reason"])
		r.Equal("test-external-connect-proxy-blocked-srv", entry.Data["role"])
		r.Equal(false, entry.Data["allow"])
	})

	t.Run("Blocks if proxy can't be parsed when the X-Upstream-Https-Proxy header is set", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})
		r := require.New(t)
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg, err := testConfig("test-external-connect-proxy-blocked-srv")
		r.NoError(err)
		cfg.Listener = l

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		internalToStripeProxy := proxyServer(cfg)
		remote := httptest.NewTLSServer(h)

		client, err := proxyClientWithConnectHeaders(internalToStripeProxy.URL, http.Header{"X-Upstream-Https-Proxy": []string{"google.com"}})
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		_, err = client.Do(req)
		r.Error(err)
		r.Contains(err.Error(), "Request rejected by proxy")
	})

	t.Run("Allows an approved proxy when the X-Upstream-Https-Proxy header is set", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})
		r := require.New(t)
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg, err := testConfig("test-external-connect-proxy-allowed-srv")
		r.NoError(err)
		cfg.Listener = l

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		proxy := proxyServer(cfg)
		logHook := proxyLogHook(cfg)

		// The External proxy is a HTTPS proxy that will be used to connect to the remote server
		externalProxy := httptest.NewUnstartedServer(BuildProxy(cfg))
		externalProxy.StartTLS()

		remote := httptest.NewTLSServer(h)
		client, err := proxyClientWithConnectHeaders(
			proxy.URL,
			http.Header{
				"X-Upstream-Https-Proxy": []string{"https://param1_username-param2-param3:password@myproxy.com:12345"},
			},
		)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		client.Do(req)

		entry := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(entry)
		r.Equal("host matched allowed domain in rule", entry.Data["decision_reason"])
		r.Equal("test-external-connect-proxy-allowed-srv", entry.Data["role"])
		r.Equal(true, entry.Data["allow"])
	})

	t.Run("Allows multiple approved proxies when the X-Upstream-Https-Proxy header is set", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})
		r := require.New(t)
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg, err := testConfig("test-external-connect-proxy-allowed-srv")
		r.NoError(err)
		cfg.Listener = l

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		proxy := proxyServer(cfg)
		logHook := proxyLogHook(cfg)

		// The External proxy is a HTTPS proxy that will be used to connect to the remote server
		externalProxy := httptest.NewUnstartedServer(BuildProxy(cfg))
		externalProxy.StartTLS()

		remote := httptest.NewTLSServer(h)
		first_client, err := proxyClientWithConnectHeaders(proxy.URL, http.Header{"X-Upstream-Https-Proxy": []string{"https://myproxy.com"}})
		r.NoError(err)

		first_req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		first_client.Do(first_req)

		second_client, err := proxyClientWithConnectHeaders(proxy.URL, http.Header{"X-Upstream-Https-Proxy": []string{"https://myproxy2.com"}})
		r.NoError(err)

		second_req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		second_client.Do(second_req)

		// Filter for only CANONICAL-PROXY-DECISION entries
		var canonicalEntries []*logrus.Entry
		for _, entry := range logHook.AllEntries() {
			if entry.Message == CanonicalProxyDecision {
				canonicalEntries = append(canonicalEntries, entry)
			}
		}
		r.Equal(2, len(canonicalEntries))

		first_entry := canonicalEntries[0]
		second_entry := canonicalEntries[1]
		r.Equal("host matched allowed domain in rule", first_entry.Data["decision_reason"])
		r.Equal("host matched allowed domain in rule", second_entry.Data["decision_reason"])
	})
}

func TestMitm(t *testing.T) {
	t.Run("CONNECT proxy", func(t *testing.T) {
		a := assert.New(t)
		r := require.New(t)

		cfg, err := testConfig("test-mitm")
		r.NoError(err)
		// We use the default test certificates from Goproxy
		mitmCa, err := tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
		r.NoError(err)
		mitmCa.Leaf, err = x509.ParseCertificate(mitmCa.Certificate[0])
		r.NoError(err)
		cfg.MitmTLSConfig = goproxy.TLSConfigFromCA(&mitmCa)
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		clientCh := make(chan bool)
		serverCh := make(chan bool)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverCh <- true
			<-serverCh
			// This handlers returns a body with a string containing all the request headers it received.
			var sb strings.Builder
			for name, values := range r.Header {
				for _, value := range values {
					sb.WriteString(name)
					sb.WriteString(": ")
					sb.WriteString(value)
					sb.WriteString(";")
				}
			}
			io.WriteString(w, sb.String())
			w.Write([]byte(sb.String()))
		})

		logHook := proxyLogHook(cfg)
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := BuildProxy(cfg)
		httpProxy := httptest.NewServer(proxy)
		remote := httptest.NewTLSServer(h)
		client, err := proxyClient(httpProxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		go func() {
			resp, err := client.Do(req)
			r.NoError(err)
			body, err := ioutil.ReadAll(resp.Body)
			r.NoError(err)
			resp.Body.Close()
			// We check the response body to see if the Mitm-Header-Inject header was injected by the Mitm handler
			a.Contains(string(body), "Accept-Language: el")
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

		// Metrics should show one successful connection and two DNS requests:
		// one for CONNECT and one for the MITM GET request (ACL check on new destination)
		tmc, ok := cfg.MetricsClient.(*metrics.MockMetricsClient)
		r.True(ok)
		i, err := tmc.GetCount("cn.atpt.total", map[string]string{"success": "true"})
		r.NoError(err)
		r.Equal(i, uint64(1))
		lookups, err := tmc.GetCount("resolver.attempts_total", make(map[string]string))
		r.NoError(err)
		r.Equal(lookups, uint64(2))
		ltime, err := tmc.GetCount("resolver.lookup_time", make(map[string]string))
		r.NoError(err)
		r.Equal(ltime, uint64(2))

		proxyDecision := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(proxyDecision)
		r.Contains(proxyDecision.Data, "proxy_type")
		r.Equal("connect", proxyDecision.Data["proxy_type"])
		proxy.Tr.CloseIdleConnections()
		// check proxyclose log entry has information about the request headers
		proxyClose := findCanonicalProxyClose(logHook.AllEntries())
		r.NotNil(proxyClose)
		r.Equal("GET", proxyClose.Data["mitm_req_method"])
		r.Contains(proxyClose.Data["mitm_req_url"], "https://127.0.0.1")
		mitmReqHeaders, ok := proxyClose.Data["mitm_req_headers"].(http.Header)
		r.True(ok)
		r.Equal("[REDACTED]", mitmReqHeaders.Get("Accept-Language"))
		r.Equal("Go-http-client/1.1", mitmReqHeaders.Get("User-Agent"))
	})

	t.Run("CONNECT proxy ACL bypass via Host header in MITM mode", func(t *testing.T) {
		a := assert.New(t)
		r := require.New(t)

		cfg, err := testConfig("test-mitm")
		r.NoError(err)

		// Enable MITM mode
		mitmCa, err := tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
		r.NoError(err)
		mitmCa.Leaf, err = x509.ParseCertificate(mitmCa.Certificate[0])
		r.NoError(err)
		cfg.MitmTLSConfig = goproxy.TLSConfigFromCA(&mitmCa)

		// Allow 127.0.0.1 where test server runs
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		// Set up smokescreen proxy
		l, err := net.Listen("tcp", "localhost:0")
		r.NoError(err)
		cfg.Listener = l

		proxy := BuildProxy(cfg)
		httpProxy := httptest.NewServer(proxy)
		defer httpProxy.Close()

		// Create a test server that will respond to requests
		remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "Response from test server")
		}))
		defer remote.Close()

		// Create HTTP client configured to use the proxy
		client, err := proxyClient(httpProxy.URL)
		r.NoError(err)

		req, err := http.NewRequest("GET", remote.URL, nil)
		r.NoError(err)

		// Attempt ACL bypass by setting Host header to a disallowed IP
		// The request URL is 127.0.0.1 (allowed), so initial CONNECT succeeds
		// But the Host header points to 10.0.0.1 (disallowed)
		req.Host = "10.0.0.1:443"

		// Send the request through the proxy
		resp, err := client.Do(req)

		r.NoError(err)
		a.Equal(http.StatusProxyAuthRequired, resp.StatusCode)
	})
}

func TestRoleLoggingInCanonicalProxyDecision(t *testing.T) {
	r := require.New(t)

	testRole := "test-local-srv"

	t.Run("HTTP requests log role", func(t *testing.T) {
		cfg, err := testConfig(testRole)
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		logHook := proxyLogHook(cfg)
		proxySrv := proxyServer(cfg)
		defer proxySrv.Close()

		testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		}))
		defer testSrv.Close()

		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		resp, err := client.Get(testSrv.URL)
		r.NoError(err)
		defer resp.Body.Close()

		r.Equal(200, resp.StatusCode)

		proxyDecision := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(proxyDecision, "Should have CANONICAL-PROXY-DECISION log")

		r.Contains(proxyDecision.Data, LogFieldRole, "CANONICAL-PROXY-DECISION should contain role field")
		r.Equal(testRole, proxyDecision.Data[LogFieldRole], "Role should match expected value")

		r.Contains(proxyDecision.Data, "proxy_type")
		r.Equal("http", proxyDecision.Data["proxy_type"])
	})

	t.Run("CONNECT requests log role", func(t *testing.T) {
		cfg, err := testConfig(testRole)
		r.NoError(err)
		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		logHook := proxyLogHook(cfg)
		proxySrv := proxyServer(cfg)
		defer proxySrv.Close()

		testSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		}))
		defer testSrv.Close()

		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		resp, err := client.Get(testSrv.URL)
		r.NoError(err)
		defer resp.Body.Close()

		r.Equal(200, resp.StatusCode)

		proxyDecision := findCanonicalProxyDecision(logHook.AllEntries())
		r.NotNil(proxyDecision, "Should have CANONICAL-PROXY-DECISION log")

		r.Contains(proxyDecision.Data, LogFieldRole, "CANONICAL-PROXY-DECISION should contain role field")
		r.Equal(testRole, proxyDecision.Data[LogFieldRole], "Role should match expected value")

		r.Contains(proxyDecision.Data, "proxy_type")
		r.Equal("connect", proxyDecision.Data["proxy_type"])
	})
}
