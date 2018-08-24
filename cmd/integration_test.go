// +build integration

package cmd

import "github.com/stretchr/testify/assert"
import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"testing"
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
	AuthorizedHost bool
	OverTls        bool
	OverConnect    bool
	Action         smokescreen.ConfigEnforcementPolicy
	ProxyPort      int
	TargetPort     int
	RandomTrace    int
}

func conformResult(t *testing.T, test *TestCase, resp *http.Response, err error) {
	a := assert.New(t)
	if test.Action == smokescreen.ConfigEnforcementPolicyEnforce {
		if test.AuthorizedHost || test.Action != smokescreen.ConfigEnforcementPolicyEnforce {
			if !a.NoError(err) {
				return
			}
			a.Equal(200, resp.StatusCode)
		} else {
			if test.OverConnect {
				a.Error(err)
			} else {
				if !a.NoError(err) {
					return
				}
				a.Equal(503, resp.StatusCode)
			}
		}
	} else {
		if !a.NoError(err) {
			return
		}
		a.Equal(200, resp.StatusCode)
	}
}

func generateRoleForTest(test *TestCase) string {
	switch test.Action {
	case smokescreen.ConfigEnforcementPolicyOpen:
		return "egressneedingservice-open"
	case smokescreen.ConfigEnforcementPolicyReport:
		return "egressneedingservice-report"
	case smokescreen.ConfigEnforcementPolicyEnforce:
		return "egressneedingservice-enforce"
	}
	return "unknown-mode"
}

func actionStringForTest(test *TestCase) string {
	switch test.Action {
	case smokescreen.ConfigEnforcementPolicyOpen:
		return "open"
	case smokescreen.ConfigEnforcementPolicyReport:
		return "report"
	case smokescreen.ConfigEnforcementPolicyEnforce:
		return "enforce"
	}
	return ""
}

func generateClientForTest(t *testing.T, test *TestCase) *http.Client {
	a := assert.New(t)

	client := cleanhttp.DefaultClient()

	if test.OverConnect {
		client.Transport.(*http.Transport).DialContext =
			func(ctx context.Context, network, addr string) (net.Conn, error) {
				fmt.Println(addr)

				var conn net.Conn

				proxyUrl := fmt.Sprintf("localhost:%d", test.ProxyPort)
				if test.OverTls {

					// Client certs
					actionString := actionStringForTest(test)
					certPath := fmt.Sprintf("testdata/pki/%s-client.pem", actionString)
					keyPath := fmt.Sprintf("testdata/pki/%s-client-key.pem", actionString)
					cert, err := tls.LoadX509KeyPair(certPath, keyPath)
					a.NoError(err)

					caBytes, err := ioutil.ReadFile("testdata/pki/ca.pem")
					a.NoError(err)
					caPool := x509.NewCertPool()
					a.True(caPool.AppendCertsFromPEM(caBytes))

					proxyTlsClientConfig := tls.Config{
						Certificates: []tls.Certificate{cert},
						RootCAs:      caPool,
					}
					connRaw, err := tls.Dial("tcp", proxyUrl, &proxyTlsClientConfig)
					a.NoError(err)
					conn = connRaw

				} else {
					connRaw, err := net.Dial(network, proxyUrl)
					a.NoError(err)
					conn = connRaw
				}

				connectProxyReq, err := http.NewRequest(
					"CONNECT",
					fmt.Sprintf("http://%s", addr),
					nil)

				if !test.OverTls { // If we're not talking to the proxy over TLS, let's use headers as identifiers
					connectProxyReq.Header.Add("X-Smokescreen-Role", generateRoleForTest(test))
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

	var host string
	if test.AuthorizedHost {
		host = "127.0.0.1"
	} else { // localhost is not in the list of authorised targets
		host = "localhost"
	}

	var req *http.Request
	var err error
	if test.OverConnect {
		// Target the external destination
		target := fmt.Sprintf("http://%s:%d", host, test.TargetPort)
		req, err = http.NewRequest("GET", target, nil)
	} else {
		// Target the proxy
		target := fmt.Sprintf("http://%s:%d", "127.0.0.1", test.ProxyPort)
		req, err = http.NewRequest("GET", target, nil)
		req.Host = fmt.Sprintf("%s:%d", host, test.TargetPort)
	}
	a.NoError(err)

	if !test.OverTls && !test.OverConnect { // If we're not talking to the proxy over TLS, let's use headers as identifiers
		req.Header.Add("X-Smokescreen-Role", generateRoleForTest(test))
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
	a := assert.New(t)

	dummyServer := NewDummyServer()
	outsideListener, err := net.Listen("tcp4", "127.0.0.1:")
	outsideListenerUrl, err := url.Parse(fmt.Sprintf("//%s", outsideListener.Addr().String()))
	a.NoError(err)
	outsideListenerPort, err := strconv.Atoi(outsideListenerUrl.Port())
	a.NoError(err)

	go dummyServer.Serve(outsideListener)

	killNonTls := startSmokescreen(t, false)
	defer killNonTls()
	killTls := startSmokescreen(t, true)
	defer killTls()

	// Generate all non-tls tests
	overTlsDomain := []bool{true, false}
	overConnectDomain := []bool{true, false}
	authorizedHostsDomain := []bool{true, false}
	actionsDomain := []smokescreen.ConfigEnforcementPolicy{
		smokescreen.ConfigEnforcementPolicyEnforce,
		smokescreen.ConfigEnforcementPolicyReport,
		smokescreen.ConfigEnforcementPolicyOpen,
	}

	for _, overTls := range overTlsDomain {
		for _, overConnect := range overConnectDomain {
			for _, authorizedHost := range authorizedHostsDomain {
				for _, action := range actionsDomain {
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

					testCase := &TestCase{
						OverTls:        overTls,
						OverConnect:    overConnect,
						AuthorizedHost: authorizedHost,
						Action:         action,
						ProxyPort:      proxyPort,
						TargetPort:     outsideListenerPort,
						RandomTrace:    rand.Int(),
					}
					executeRequestForTest(t, testCase)
					if t.Failed() {
						fmt.Printf("%+v\n", testCase)
						return
					}
				}
			}
		}
	}
}

func startSmokescreen(t *testing.T, useTls bool) func() {
	a := assert.New(t)

	var conf *smokescreen.Config
	var err error
	if useTls {
		conf, err = ConfigFromArgs(nil, []string{
			"--server-ip=127.0.0.1",
			fmt.Sprintf("--server-port=%d", plainSmokescreenPort),
			"--egress-acl-file=testdata/sample_config.yaml",
			"--danger-allow-access-to-private-ranges",
			"--error-message-on-deny=\"egress denied: go see doc at https://example.com/egressproxy\"",
		})
	} else {
		conf, err = ConfigFromArgs(nil, []string{
			"--server-ip=127.0.0.1",
			fmt.Sprintf("--server-port=%d", tlsSmokescreenPort),
			"--egress-acl-file=testdata/sample_config.yaml",
			"--danger-allow-access-to-private-ranges",
			"--error-message-on-deny=\"egress denied: go see doc at https://example.com/egressproxy\"",
			"--tls-server-bundle-file=testdata/pki/server-bundle.pem",
			"--tls-client-ca-file=testdata/pki/ca.pem",
			"--tls-crl-file=testdata/pki/crl.pem",
		})
	}

	a.NoError(err)
	kill := make(chan interface{})
	go smokescreen.StartWithConfig(conf, kill)
	return func() { kill <- syscall.SIGHUP }
}
