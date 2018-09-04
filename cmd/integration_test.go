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
	"net/url"
	"strconv"
	"syscall"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stripe/smokescreen/pkg/smokescreen"
)

var plainSmokescreenPort = 4520
var tlsSmokescreenPort = 4521

type DummyHandler struct{}

func (s *DummyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	io.WriteString(rw, "ok")
}

func NewDummyServer() *http.Server {
	return &http.Server{
		Handler: &DummyHandler{},
	}
}

type TestCase struct {
	ExpectAllow bool
	OverTls     bool
	OverConnect bool
	ProxyPort   int
	TargetPort  int
	RandomTrace int
	Host        string
	RoleName    string
}

func conformResult(t *testing.T, test *TestCase, resp *http.Response, err error) {
	a := assert.New(t)
	if test.ExpectAllow {
		if !a.NoError(err) {
			return
		}
		a.Equal(200, resp.StatusCode)
	} else {
		if !a.NoError(err) {
			return
		}
		a.Equal(503, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if !a.NoError(err) {
			return
		}
		a.Contains(string(body), "egress proxying denied to host")
		a.Contains(string(body), "moar ctx")
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

				proxyUrl := fmt.Sprintf("localhost:%d", test.ProxyPort)
				if test.OverTls {
					var certs []tls.Certificate

					if test.RoleName != "" {
						// Client certs
						certPath := fmt.Sprintf("testdata/pki/%s-client.pem", test.RoleName)
						keyPath := fmt.Sprintf("testdata/pki/%s-client-key.pem", test.RoleName)
						cert, err := tls.LoadX509KeyPair(certPath, keyPath)
						a.NoError(err)

						certs = append(certs, cert)
					}

					caBytes, err := ioutil.ReadFile("testdata/pki/ca.pem")
					a.NoError(err)
					caPool := x509.NewCertPool()
					a.True(caPool.AppendCertsFromPEM(caBytes))

					proxyTlsClientConfig := tls.Config{
						Certificates: certs,
						RootCAs:      caPool,
					}
					connRaw, err := tls.Dial("tcp", proxyUrl, &proxyTlsClientConfig)
					a.NoError(err)
					conn = connRaw

				} else {
					connRaw, err := net.Dial(network, proxyUrl)
					a.NoError(err)
					conn = connRaw

					// If we're not talking to the proxy over TLS, let's use headers as identifiers
					if test.RoleName != "" {
						connectProxyReq.Header.Add("X-Smokescreen-Role", "egressneedingservice-"+test.RoleName)
					}
					connectProxyReq.Header.Add("X-Random-Trace", fmt.Sprintf("%d", test.RandomTrace))
				}

				a.NoError(err)
				buf := bytes.NewBuffer([]byte{})
				connectProxyReq.Write(buf)
				buf.Write([]byte{'\n'})
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
		target := fmt.Sprintf("http://%s:%d", "127.0.0.1", test.ProxyPort)
		req, err = http.NewRequest("GET", target, nil)
		req.Host = fmt.Sprintf("%s:%d", test.Host, test.TargetPort)
	}
	a.NoError(err)

	if !test.OverTls && !test.OverConnect { // If we're not talking to the proxy over TLS, let's use headers as identifiers
		req.Header.Add("X-Smokescreen-Role", "egressneedingservice-"+test.RoleName)
		req.Header.Add("X-Random-Trace", fmt.Sprintf("%d", test.RandomTrace))
	}
	return req
}

func executeRequestForTest(t *testing.T, test *TestCase) {
	client := generateClientForTest(t, test)
	req := generateRequestForTest(t, test)

	resp, err := client.Do(req)
	conformResult(t, test, resp, err)

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

	for _, useTls := range []bool{true, false} {
		kill, err := startSmokescreen(t, useTls)
		require.NoError(t, err)
		defer kill()
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

			var proxyPort int
			if overTls {
				proxyPort = tlsSmokescreenPort
			} else {
				proxyPort = plainSmokescreenPort
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
						ProxyPort:   proxyPort,
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
			ProxyPort:   plainSmokescreenPort,
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
		testCase.RandomTrace = rand.Int()
		executeRequestForTest(t, testCase)
		if t.Failed() {
			fmt.Printf("%+v\n", testCase)
			return
		}
	}
}

func startSmokescreen(t *testing.T, useTls bool) (func(), error) {
	args := []string{
		"smokescreen",
		"--listen-ip=127.0.0.1",
		"--egress-acl-file=testdata/sample_config.yaml",
		"--danger-allow-access-to-private-ranges",
		"--additional-error-message-on-deny=moar ctx",
		"--deny-range=127.0.0.2/32",
	}

	var conf *smokescreen.Config
	var err error
	if useTls {
		args = append(args,
			fmt.Sprintf("--listen-port=%d", plainSmokescreenPort),
		)
		conf, err = NewConfiguration(args, nil)
	} else {
		args = append(args,
			fmt.Sprintf("--listen-port=%d", tlsSmokescreenPort),
			"--tls-server-bundle-file=testdata/pki/server-bundle.pem",
			"--tls-client-ca-file=testdata/pki/ca.pem",
			"--tls-crl-file=testdata/pki/crl.pem",
		)

		conf, err = NewConfiguration(args, nil)
	}

	if err != nil {
		return nil, err
	}

	kill := make(chan interface{})
	go smokescreen.StartWithConfig(conf, kill)
	return func() { kill <- syscall.SIGHUP }, nil
}
