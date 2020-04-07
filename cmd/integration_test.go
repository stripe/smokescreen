// +build !nointegration

package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
)

type DummyHandler struct{}

func (s *DummyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(50 * time.Millisecond)
	io.WriteString(rw, "okok")
}

func NewDummyServer() *http.Server {
	return &http.Server{
		Handler: &DummyHandler{},
	}
}

// RoleFromRequest implementations
func testRFRHeader(req *http.Request) (string, error) {
	idHeader := req.Header["X-Smokescreen-Role"]
	if len(idHeader) != 1 {
		return "", smokescreen.MissingRoleError(fmt.Sprintf("Expected 1 header, got %d", len(idHeader)))
	}
	return idHeader[0], nil
}
func testRFRCert(req *http.Request) (string, error) {
	if len(req.TLS.PeerCertificates) == 0 {
		return "", smokescreen.MissingRoleError("client did not provide certificate")
	}
	return req.TLS.PeerCertificates[0].Subject.CommonName, nil
}

type TestCase struct {
	ExpectAllow   bool
	Action        acl.EnforcementPolicy
	ExpectStatus  int
	OverTls       bool
	OverConnect   bool
	ProxyURL      string
	TargetPort    int
	RandomTrace   int
	TargetHost    string
	TargetScheme  string
	RoleName      string
	UpstreamProxy string
}

func conformResult(t *testing.T, test *TestCase, resp *http.Response, err error, logs []*logrus.Entry) {
	t.Logf("HTTP Response: %#v", resp)

	a := assert.New(t)
	if test.ExpectAllow {
		// In some cases we expect the proxy to allow the request but the upstream to return an error
		if test.ExpectStatus != 0 {
			if resp == nil {
				t.Fatal(err)
			}
			a.Equal(test.ExpectStatus, resp.StatusCode, "Expected HTTP response code did not match")
			return
		}
		// CONNECT requests which return a non-200 return an error and a nil response
		if resp == nil {
			a.Error(err)
			return
		}
		a.Equal(http.StatusOK, resp.StatusCode, "HTTP Response code should indicate success.")
	} else {
		// CONNECT requests which return a non-200 return an error and a nil response
		if resp == nil {
			a.Error(err)
			return
		}
		// If there is a response returned, it should contain smokescreen's error message
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		a.Contains(string(body), "denied")
		a.Contains(string(body), "more ctx")
	}

	var entries []*logrus.Entry
	for _, entry := range logs {
		if entry.Level < logrus.WarnLevel {
			a.Failf("unexpected log line more severe than Warn", "%v", entry)
		} else if entry.Level < logrus.DebugLevel {
			entries = append(entries, entry)
		}
	}

	if len(entries) > 0 {
		lastEntryIndex := len(entries) - 1
		entry := entries[lastEntryIndex]
		a.Equal(entry.Message, smokescreen.LOGLINE_CANONICAL_PROXY_DECISION)

		a.Contains(entry.Data, "allow")
		a.Equal(test.ExpectAllow, entries[lastEntryIndex].Data["allow"])

		a.Contains(entry.Data, "proxy_type")
		if test.OverConnect {
			a.Equal("connect", entry.Data["proxy_type"])
		} else {
			a.Equal("http", entry.Data["proxy_type"])
		}

		a.Contains(entry.Data, "requested_host")
		a.Equal(fmt.Sprintf("%s:%d", test.TargetHost, test.TargetPort), entry.Data["requested_host"])
	}
}

func generateRoleForAction(action acl.EnforcementPolicy) string {
	switch action {
	case acl.Open:
		return "open"
	case acl.Report:
		return "report"
	case acl.Enforce:
		return "enforce"
	}
	panic("unknown-mode")
}

func generateClientForTest(t *testing.T, test *TestCase) *http.Client {
	a := assert.New(t)

	var client *http.Client
	proxyURL, err := url.Parse(test.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}

	if test.OverConnect {
		client = cleanhttp.DefaultClient()
		client.Transport.(*http.Transport).DialContext =
			func(ctx context.Context, network, addr string) (net.Conn, error) {
				var conn net.Conn

				connectProxyReq, err := http.NewRequest(
					"CONNECT",
					fmt.Sprintf("%s://%s", test.TargetScheme, addr),
					nil)
				if err != nil {
					return nil, err
				}

				if test.OverTls {
					var certs []tls.Certificate

					// Load client cert for role
					if test.RoleName != "" {
						certPath := fmt.Sprintf("testdata/pki/%s-client.pem", test.RoleName)
						keyPath := fmt.Sprintf("testdata/pki/%s-client-key.pem", test.RoleName)
						cert, err := tls.LoadX509KeyPair(certPath, keyPath)
						if err != nil {
							return nil, err
						}
						certs = append(certs, cert)
					}

					caBytes, err := ioutil.ReadFile("testdata/pki/ca.pem")
					if err != nil {
						return nil, err
					}
					caPool := x509.NewCertPool()
					a.True(caPool.AppendCertsFromPEM(caBytes))

					proxyTlsClientConfig := tls.Config{
						Certificates: certs,
						RootCAs:      caPool,
					}
					connRaw, err := tls.Dial("tcp", proxyURL.Host, &proxyTlsClientConfig)
					if err != nil {
						return nil, err
					}
					conn = connRaw
				} else {
					connRaw, err := net.Dial(network, proxyURL.Host)
					if err != nil {
						return nil, err
					}
					conn = connRaw

					// If we're not talking to the proxy over TLS, let's use headers as identifiers
					connectProxyReq.Header.Add("X-Smokescreen-Role", "egressneedingservice-"+test.RoleName)
					connectProxyReq.Header.Add("X-Smokescreen-Trace-ID", fmt.Sprintf("%d", test.RandomTrace))
				}

				t.Logf("connect request: %#v", connectProxyReq)
				connectProxyReq.Write(conn)

				// Read the response from the connect request and return an error for any non-200
				// from smokescreen
				br := bufio.NewReader(conn)
				resp, err := http.ReadResponse(br, connectProxyReq)
				if err != nil {
					conn.Close()
					return nil, err
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					resp, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return nil, err
					}
					conn.Close()
					return nil, errors.New(string(resp))
				}
				return conn, nil
			}
	} else {
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}
	}
	return client
}

func generateRequestForTest(t *testing.T, test *TestCase) *http.Request {
	a := assert.New(t)

	target := fmt.Sprintf("%s://%s:%d", test.TargetScheme, test.TargetHost, test.TargetPort)
	req, err := http.NewRequest("GET", target, nil)
	a.NoError(err)

	if !test.OverTls && !test.OverConnect {
		// If we're not talking to the proxy over TLS, let's use headers as identifiers
		req.Header.Add("X-Smokescreen-Role", "egressneedingservice-"+test.RoleName)
		req.Header.Add("X-Smokescreen-Trace-ID", fmt.Sprintf("%d", test.RandomTrace))
	}

	t.Logf("HTTP Request: %#v", req)
	return req
}

func executeRequestForTest(t *testing.T, test *TestCase, logHook *logrustest.Hook) (*http.Response, error) {
	t.Logf("Executing Request for test case %#v", test)

	logHook.Reset()

	os.Setenv("http_proxy", test.UpstreamProxy)
	os.Setenv("https_proxy", test.UpstreamProxy)
	defer os.Unsetenv("http_proxy")
	defer os.Unsetenv("https_proxy")

	client := generateClientForTest(t, test)
	req := generateRequestForTest(t, test)

	return client.Do(req)
}

func TestSmokescreenIntegration(t *testing.T) {
	r := require.New(t)

	// This local listener is used as the `authorizedHost` and given to
	// dummyServer to return simple HTTP requests.
	outsideListener, err := net.Listen("tcp4", "127.0.0.1:")
	outsideListenerUrl, err := url.Parse(fmt.Sprintf("http://%s", outsideListener.Addr().String()))
	r.NoError(err)
	outsideListenerPort, err := strconv.Atoi(outsideListenerUrl.Port())
	r.NoError(err)

	dummyServer := NewDummyServer()
	go dummyServer.Serve(outsideListener)

	var logHook logrustest.Hook
	servers := map[bool]*httptest.Server{}
	for _, useTls := range []bool{true, false} {
		server, err := startSmokescreen(t, useTls, &logHook)
		require.NoError(t, err)
		defer server.Close()
		servers[useTls] = server
	}

	// Generate all non-tls tests
	overTlsDomain := []bool{true, false}
	overConnectDomain := []bool{true, false}
	authorizedHostsDomain := []bool{true, false}
	actionsDomain := []acl.EnforcementPolicy{
		acl.Enforce,
		acl.Report,
		acl.Open,
	}

	var testCases []*TestCase

	// This generates all the permutations for the common test cases
	for _, overConnect := range overConnectDomain {
		for _, overTls := range overTlsDomain {
			// Do not support this test case
			if overTls && !overConnect {
				continue
			}

			for _, authorizedHost := range authorizedHostsDomain {
				var host string
				var port int
				if authorizedHost {
					host = "127.0.0.1"
					port = outsideListenerPort
				} else {
					host = "api.github.com"
					port = 80
				}

				for _, action := range actionsDomain {
					var expectAllow bool
					// If a host is authorized, it is allowed by the config
					// and will always be allowed.
					if authorizedHost {
						expectAllow = true
					}

					// Report and open modes should always allow requests.
					if action != acl.Enforce {
						expectAllow = true
					}

					targetScheme := "http"
					if overTls {
						targetScheme = "https"
					}

					testCase := &TestCase{
						ExpectAllow:  expectAllow,
						Action:       action,
						OverTls:      overTls,
						OverConnect:  overConnect,
						ProxyURL:     servers[overTls].URL,
						TargetPort:   port,
						TargetHost:   host,
						TargetScheme: targetScheme,
						RoleName:     generateRoleForAction(action),
					}
					testCases = append(testCases, testCase)
				}
			}
		}

		baseCase := TestCase{
			OverConnect:  overConnect,
			ProxyURL:     servers[false].URL,
			TargetPort:   outsideListenerPort,
			TargetScheme: "http",
		}

		// Empty roles should default deny per the test config
		noRoleDenyCase := baseCase
		noRoleDenyCase.TargetHost = "127.0.0.1"
		noRoleDenyCase.ExpectAllow = false

		// Unknown roles should default deny per the test config
		unknownRoleDenyCase := baseCase
		unknownRoleDenyCase.TargetHost = "127.0.0.1"
		unknownRoleDenyCase.RoleName = "unknown"
		unknownRoleDenyCase.ExpectAllow = false

		// This must be a global unicast, non-loopback address or other IP rules will
		// block it regardless of the specific configuration we're trying to test.
		badIPRangeCase := baseCase
		badIPRangeCase.TargetHost = "1.1.1.1"
		badIPRangeCase.ExpectAllow = false
		badIPRangeCase.RoleName = generateRoleForAction(acl.Open)

		// This must be a global unicast, non-loopback address or other IP rules will
		// block it regardless of the specific configuration we're trying to test.
		badIPAddressCase := baseCase
		badIPAddressCase.TargetHost = "1.0.0.1"
		badIPAddressCase.TargetPort = 123
		badIPAddressCase.ExpectAllow = false
		badIPAddressCase.RoleName = generateRoleForAction(acl.Open)

		// We expect this URL to always return a non-200 status code so that
		// this test will fail if we're not respecting the UpstreamProxy setting
		// and instead going straight to this host.
		if overConnect {
			proxyCase := baseCase
			proxyCase.TargetScheme = "https"
			proxyCase.TargetHost = "aws.s3.amazonaws.com"
			proxyCase.TargetPort = 443
			proxyCase.UpstreamProxy = outsideListenerUrl.String()
			proxyCase.ExpectAllow = true
			proxyCase.RoleName = generateRoleForAction(acl.Open)
			testCases = append(testCases, &proxyCase)
		}

		testCases = append(testCases,
			&unknownRoleDenyCase, &noRoleDenyCase,
			&badIPRangeCase, &badIPAddressCase,
		)
	}

	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			testCase.RandomTrace = rand.Int()
			resp, err := executeRequestForTest(t, testCase, &logHook)
			conformResult(t, testCase, resp, err, logHook.AllEntries())
		})
	}
}

func findLogEntry(entries []*logrus.Entry, msg string) *logrus.Entry {
	for _, entry := range entries {
		if entry.Message == msg {
			return entry
		}
	}
	return nil
}

func startSmokescreen(t *testing.T, useTls bool, logHook logrus.Hook) (*httptest.Server, error) {
	args := []string{
		"smokescreen",
		"--listen-ip=127.0.0.1",
		"--egress-acl-file=testdata/sample_config.yaml",
		"--additional-error-message-on-deny=more ctx",
		"--deny-range=1.1.1.1/32",
		"--allow-range=127.0.0.1/32",
		"--deny-address=1.0.0.1:123",
	}

	if useTls {
		args = append(args,
			"--tls-server-bundle-file=testdata/pki/server-bundle.pem",
			"--tls-client-ca-file=testdata/pki/ca.pem",
			"--tls-crl-file=testdata/pki/crl.pem",
		)
	}

	conf, err := NewConfiguration(args, nil)
	if err != nil {
		t.Fatalf("Failed to create configuration: %v", err)
	}

	if useTls {
		conf.RoleFromRequest = testRFRCert
	} else {
		conf.RoleFromRequest = testRFRHeader
	}

	conf.ConnectTimeout = time.Second

	fmt.Printf("2 %#v\n", conf)
	conf.Log.AddHook(logHook)

	handler := smokescreen.BuildProxy(conf)
	server := httptest.NewUnstartedServer(handler)

	if useTls {
		server.TLS = conf.TlsConfig
		server.StartTLS()
	} else {
		server.Start()
	}

	return server, nil
}
