// +build !nointegration

package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stripe/smokescreen/pkg/smokescreen"
)

type DummyHandler struct{}

func (s *DummyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	io.WriteString(rw, "ok")
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
	ExpectAllow bool
	OverTls     bool
	OverConnect bool
	ProxyURL    string
	TargetPort  int
	RandomTrace int
	Host        string
	RoleName    string
}

func conformResult(t *testing.T, test *TestCase, resp *http.Response, err error, logs []*logrus.Entry) {
	t.Logf("HTTP Response: %#v", resp)

	a := assert.New(t)
	if test.ExpectAllow {
		if !a.NoError(err) {
			return
		}
		a.Equal(200, resp.StatusCode, "HTTP Response code should indicate success.")
	} else {
		if !a.NoError(err) {
			return
		}
		a.Equal(503, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if !a.NoError(err) {
			return
		}
		a.Contains(string(body), "denied")
		a.Contains(string(body), "moar ctx")
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
		a.Equal(fmt.Sprintf("%s:%d", test.Host, test.TargetPort), entry.Data["requested_host"])
	}
}

func generateRoleForAction(action smokescreen.ConfigEnforcementPolicy) string {
	switch action {
	case smokescreen.ConfigEnforcementPolicyOpen:
		return "open"
	case smokescreen.ConfigEnforcementPolicyReport:
		return "report"
	case smokescreen.ConfigEnforcementPolicyEnforce:
		return "enforce"
	}
	panic("unknown-mode")
}

func generateClientForTest(t *testing.T, test *TestCase) *http.Client {
	a := assert.New(t)

	client := cleanhttp.DefaultClient()

	if test.OverConnect {
		client.Transport.(*http.Transport).DialContext =
			func(ctx context.Context, network, addr string) (net.Conn, error) {
				fmt.Println(addr)

				var conn net.Conn

				connectProxyReq, err := http.NewRequest(
					"CONNECT",
					fmt.Sprintf("http://%s", addr),
					nil)
				if err != nil {
					return nil, err
				}

				proxyURL, err := url.Parse(test.ProxyURL)
				if err != nil {
					return nil, err
				}
				if test.OverTls {
					var certs []tls.Certificate

					if test.RoleName != "" {
						// Client certs
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
					connectProxyReq.Header.Add("X-Random-Trace", fmt.Sprintf("%d", test.RandomTrace))
				}

				buf := bytes.NewBuffer([]byte{})
				connectProxyReq.Write(buf)
				buf.Write([]byte{'\n'})

				t.Logf("connect request: %#v", buf.String())

				buf.WriteTo(conn)

				// Todo: Catch the proxy response here and act on it.
				return conn, nil
			}
	}
	return client
}

func generateRequestForTest(t *testing.T, test *TestCase) *http.Request {
	a := assert.New(t)

	var req *http.Request
	var err error
	if test.OverConnect {
		// Target the external destination
		target := fmt.Sprintf("http://%s:%d", test.Host, test.TargetPort)
		req, err = http.NewRequest("GET", target, nil)
	} else {
		// Target the proxy
		req, err = http.NewRequest("GET", test.ProxyURL, nil)
		req.Host = fmt.Sprintf("%s:%d", test.Host, test.TargetPort)
	}
	a.NoError(err)

	if !test.OverTls && !test.OverConnect { // If we're not talking to the proxy over TLS, let's use headers as identifiers
		req.Header.Add("X-Smokescreen-Role", "egressneedingservice-"+test.RoleName)
		req.Header.Add("X-Random-Trace", fmt.Sprintf("%d", test.RandomTrace))
	}

	t.Logf("HTTP Request: %#v", req)
	return req
}

func executeRequestForTest(t *testing.T, test *TestCase, logHook *logrustest.Hook) {
	t.Logf("Executing Request for test case %#v", test)

	logHook.Reset()
	client := generateClientForTest(t, test)
	req := generateRequestForTest(t, test)

	resp, err := client.Do(req)
	conformResult(t, test, resp, err, logHook.AllEntries())
}

func TestSmokescreenIntegration(t *testing.T) {
	r := require.New(t)

	dummyServer := NewDummyServer()
	outsideListener, err := net.Listen("tcp4", "127.0.0.1:")
	outsideListenerUrl, err := url.Parse(fmt.Sprintf("//%s", outsideListener.Addr().String()))
	r.NoError(err)
	outsideListenerPort, err := strconv.Atoi(outsideListenerUrl.Port())
	r.NoError(err)

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
	actionsDomain := []smokescreen.ConfigEnforcementPolicy{
		smokescreen.ConfigEnforcementPolicyEnforce,
		smokescreen.ConfigEnforcementPolicyReport,
		smokescreen.ConfigEnforcementPolicyOpen,
	}

	var testCases []*TestCase

	for _, overConnect := range overConnectDomain {
		for _, overTls := range overTlsDomain {
			if overTls && !overConnect {
				// Is a super sketchy use case, let's not do that.
				continue
			}

			for _, authorizedHost := range authorizedHostsDomain {
				var host string
				if authorizedHost {
					host = "127.0.0.1"
				} else { // localhost is not in the list of authorized targets
					host = "localhost"
				}

				for _, action := range actionsDomain {
					testCase := &TestCase{
						ExpectAllow: authorizedHost || action != smokescreen.ConfigEnforcementPolicyEnforce,
						OverTls:     overTls,
						OverConnect: overConnect,
						ProxyURL:    servers[overTls].URL,
						TargetPort:  outsideListenerPort,
						Host:        host,
						RoleName:    generateRoleForAction(action),
					}
					testCases = append(testCases, testCase)
				}
			}
		}

		baseCase := TestCase{
			OverConnect: overConnect,
			ProxyURL:    servers[false].URL,
			TargetPort:  outsideListenerPort,
		}

		noRoleDenyCase := baseCase
		noRoleDenyCase.Host = "127.0.0.1"
		noRoleDenyCase.ExpectAllow = false

		noRoleAllowCase := baseCase
		noRoleAllowCase.Host = "localhost"
		noRoleAllowCase.ExpectAllow = true

		unknownRoleDenyCase := noRoleDenyCase
		unknownRoleDenyCase.RoleName = "unknown"

		unknownRoleAllowCase := noRoleAllowCase
		unknownRoleAllowCase.RoleName = "unknown"

		badIPCase := baseCase
		badIPCase.Host = "127.0.0.2"
		badIPCase.ExpectAllow = false
		badIPCase.RoleName = generateRoleForAction(smokescreen.ConfigEnforcementPolicyOpen)

		testCases = append(testCases,
			&unknownRoleAllowCase, &unknownRoleDenyCase,
			&noRoleAllowCase, &noRoleDenyCase,
			&badIPCase,
		)
	}

	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			testCase.RandomTrace = rand.Int()
			executeRequestForTest(t, testCase, &logHook)
		})
	}
}

func startSmokescreen(t *testing.T, useTls bool, logHook logrus.Hook) (*httptest.Server, error) {
	args := []string{
		"smokescreen",
		"--listen-ip=127.0.0.1",
		"--egress-acl-file=testdata/sample_config.yaml",
		"--additional-error-message-on-deny=moar ctx",
		"--deny-range=127.0.0.2/32",
		"--allow-range=127.0.0.1/32",
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
