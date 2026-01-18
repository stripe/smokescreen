//go:build !nointegration
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
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

var ProxyTargetHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	time.Sleep(50 * time.Millisecond)
	io.WriteString(w, "okok")
})

var mitmReflectingHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Echo back specific headers that Smokescreen might add
	if val := r.Header.Get("X-Mitm-Test"); val != "" {
		w.Header().Set("Echo-X-Mitm-Test", val)
	}
	if val := r.Header.Get("X-Another-Mitm"); val != "" {
		w.Header().Set("Echo-X-Another-Mitm", val)
	}
	// Optionally log received headers for debugging during test development
	// log.Printf("mitmReflectingHandler received headers: %v", r.Header)
	io.WriteString(w, "mitm-ok")
})

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
	OverTLS       bool
	OverConnect   bool
	ProxyURL      string
	RandomTrace   int
	TargetURL     string
	RoleName      string
	UpstreamProxy string

	// Fields for MITM testing
	ExpectEchoHeaders      map[string]string // Expected echoed headers in response
	ExpectDetailedLogs     bool              // True if detailed logs are expected for this request
	ShouldNotHaveDetailedLogs bool           // True if detailed logs should NOT be present (for control cases)
	MitmConfiguredHeaderKey string           // The key of the header configured in mitm_domains.add_headers

	// Fields for External Proxy testing
	HeaderToAdd map[string]string // Headers to add to the outgoing request to Smokescreen

	// Fields for enhanced log validation
	ExpectedLogReason  string // Expected substring in CANONICAL-PROXY-DECISION's decision_reason
	ExpectedLogProject string // Expected project in CANONICAL-PROXY-DECISION

	// Fields for redirect testing
	ExpectedResponseBodyContains []string          // Substrings expected in the final response body
	ExpectedFinalQueryParams     map[string]string // Query params expected at the final destination (checked in body)
}

// validateProxyResponse validates tests cases and expected responses from TestSmokescreenIntegration
func validateProxyResponse(t *testing.T, test *TestCase, resp *http.Response, err error, logs []*logrus.Entry) {
	t.Logf("HTTP Response: %#v", resp)
	a := assert.New(t)

	// MITM Header Validation
	if test.ExpectEchoHeaders != nil {
		require.NotNil(t, resp, "Response should not be nil for MITM header check")
		for k, v := range test.ExpectEchoHeaders {
			a.Equal(v, resp.Header.Get(k), fmt.Sprintf("Expected echo header %s not found or value mismatch", k))
		}
	}

	if test.ExpectAllow {
		// In some cases we expect the proxy to allow the request but the upstream to return an error
		// or for MITM tests, the body might be different
		if test.ExpectStatus != 0 {
			require.NotNil(t, resp, "Response should not be nil when expecting a specific status")
			a.Equal(test.ExpectStatus, resp.StatusCode, "Expected HTTP response code did not match")

			// For MITM or redirect tests, we might not want to return early, to allow for further validation.
			isMitmOrRedirectTest := test.MitmConfiguredHeaderKey != "" || test.ExpectEchoHeaders != nil || len(test.ExpectedResponseBodyContains) > 0
			if !isMitmOrRedirectTest {
				return
			}
		}
		// CONNECT requests which return a non-200 return an error and a nil response
		if resp == nil && !test.OverConnect { // Normal HTTP requests should have a response if allowed
			t.Fatal("Response is nil for an allowed non-CONNECT request", err)
		}
		if resp != nil { // For CONNECT, resp can be nil if an error occurred during tunnel setup after initial 200 OK
			a.Equal(test.ExpectStatus, resp.StatusCode, "HTTP Response code should indicate success.")

			// Redirect specific body/param validation
			if len(test.ExpectedResponseBodyContains) > 0 {
				bodyBytes, readErr := ioutil.ReadAll(resp.Body)
				require.NoError(t, readErr, "Failed to read response body for validation")
				defer resp.Body.Close()
				bodyString := string(bodyBytes)
				for _, substring := range test.ExpectedResponseBodyContains {
					a.Contains(bodyString, substring, "Response body missing expected substring")
				}
			}
			if test.ExpectedFinalQueryParams != nil {
				// This assumes query params are echoed in the body as "Params: key1=val1&key2=val2"
				// This check might need to be more robust based on actual final server echo format.
				bodyBytes, readErr := ioutil.ReadAll(resp.Body) // Re-read if not already read
				if readErr == nil { // if body was already read and closed, this will fail, handle gracefully
					defer resp.Body.Close()
					bodyString := string(bodyBytes)
					for k, v := range test.ExpectedFinalQueryParams {
						paramCheck := fmt.Sprintf("%s=%s", k, v)
						a.Contains(bodyString, paramCheck, fmt.Sprintf("Final response body missing echoed query param: %s", paramCheck))
					}
				} else if len(test.ExpectedResponseBodyContains) == 0 { // if body wasn't read for other checks
				    t.Logf("Could not read body for query param check, error: %v", readErr)
				}
			}


		} else if test.OverConnect && test.ExpectStatus == http.StatusOK {
			// If it's a CONNECT request expecting OK, but resp is nil, means an error post-tunnel.
			// This can happen if the upstream target server is problematic, but Smokescreen allowed the CONNECT.
			// The error 'err' will contain details.
			a.NoError(err, "CONNECT request expecting OK resulted in nil response and an error")
		}

	} else {
		// CONNECT requests which return a non-200 return an error and a nil response
		if resp == nil {
			a.Error(err) // Expecting an error if response is nil for denied requests
			return
		}
		// If there is a response returned, it should contain smokescreen's error message
		body, errReadBody := ioutil.ReadAll(resp.Body)
		if errReadBody != nil {
			t.Fatal(errReadBody)
		}
		defer resp.Body.Close()
		a.Contains(string(body), "denied")
		a.Contains(string(body), "additional_error_message_validation_key")
		a.Equal(test.ExpectStatus, resp.StatusCode, "Expected status did not match actual response code")
	}

	// Log validation
	var entries []*logrus.Entry
	entries = append(entries, logs...)
	foundCanonicalDecision := false
	foundDetailedLogEvidence := false

	if len(entries) > 0 {
		for _, entry := range entries {
			if entry.Message == smokescreen.CanonicalProxyDecision {
				foundCanonicalDecision = true
				a.Contains(entry.Data, "allow", "Canonical log missing 'allow' field")
				a.Equal(test.ExpectAllow, entry.Data["allow"], "Canonical log 'allow' field mismatch")

				a.Contains(entry.Data, "proxy_type", "Canonical log missing 'proxy_type' field")
				if test.OverConnect {
					a.Equal("connect", entry.Data["proxy_type"], "Canonical log 'proxy_type' mismatch for CONNECT")
				} else {
					a.Equal("http", entry.Data["proxy_type"], "Canonical log 'proxy_type' mismatch for HTTP")
				}

				a.Contains(entry.Data, "requested_host", "Canonical log missing 'requested_host' field")
				u, _ := url.Parse(test.TargetURL)
				a.Equal(fmt.Sprintf("%s:%s", u.Hostname(), u.Port()), entry.Data["requested_host"], "Canonical log 'requested_host' mismatch")

				// Assert decision_reason
				// For allowed requests, ExpectedLogReason might be empty or a generic allow reason.
				// For denied requests, it's more critical.
				if test.ExpectedLogReason != "" {
					reason, ok := entry.Data["decision_reason"].(string)
					a.True(ok, "decision_reason field is missing or not a string in canonical log")
					if ok { // Proceed only if type assertion was successful
						a.Contains(reason, test.ExpectedLogReason, "Canonical log 'decision_reason' mismatch")
					}
				} else if !test.ExpectAllow {
					// If it's a denied request, we should generally expect a reason.
					// This ensures tests are updated to provide one.
					a.NotEmpty(entry.Data["decision_reason"], "decision_reason should not be empty for a denied request; please specify ExpectedLogReason in test case")
				}


				// Assert project
				if test.ExpectedLogProject != "" {
					project, ok := entry.Data["project"].(string)
					a.True(ok, "project field is missing or not a string in canonical log")
					if ok { // Proceed only if type assertion was successful
						a.Equal(test.ExpectedLogProject, project, "Canonical log 'project' mismatch")
					}
				} else {
					// All canonical decisions should have a project.
					a.NotEmpty(entry.Data["project"], "project field should not be empty in canonical log; please specify ExpectedLogProject in test case")
				}
			}

			// Check for detailed logging evidence (presence of the MITM-configured header key in log fields)
			// This is a heuristic. A more robust check might look for a specific "detailed logging" message if Smokescreen emits one.
			if test.MitmConfiguredHeaderKey != "" && entry.Data[test.MitmConfiguredHeaderKey] != nil {
				t.Logf("Found MITM header key '%s' in log entry fields: %v", test.MitmConfiguredHeaderKey, entry.Data)
				foundDetailedLogEvidence = true
			}
			// Alternative check: look for a hypothetical specific message
			// if entry.Message == "Detailed HTTP logging enabled for request" {
			// 	foundDetailedLogEvidence = true
			// }

		}
	}
	a.True(foundCanonicalDecision, "Expected canonical proxy decision log entry was not found")

	if test.ExpectDetailedLogs {
		a.True(foundDetailedLogEvidence, fmt.Sprintf("Expected detailed logging evidence (e.g., header '%s' in log fields) but found none.", test.MitmConfiguredHeaderKey))
	}
	if test.ShouldNotHaveDetailedLogs {
		a.False(foundDetailedLogEvidence, fmt.Sprintf("Expected no detailed logging evidence (e.g., header '%s' in log fields) but found some.", test.MitmConfiguredHeaderKey))
	}
}

func generateRoleForPolicy(action acl.EnforcementPolicy) string {
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
					test.TargetURL,
					nil)
				if err != nil {
					return nil, err
				}

				if test.OverTLS {
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

					proxyTLSClientConfig := tls.Config{
						Certificates: certs,
						RootCAs:      caPool,
					}
					connRaw, err := tls.Dial("tcp", proxyURL.Host, &proxyTLSClientConfig)
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

	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	return client
}

func generateRequestForTest(t *testing.T, test *TestCase) *http.Request {
	a := assert.New(t)

	req, err := http.NewRequest("GET", test.TargetURL, nil)
	a.NoError(err)

	if !test.OverTLS && !test.OverConnect {
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

	client := generateClientForTest(t, test)
	req := generateRequestForTest(t, test)

	// Add any custom headers for this test case
	if test.HeaderToAdd != nil {
		for k, v := range test.HeaderToAdd {
			req.Header.Add(k, v)
			t.Logf("Added header to request: %s: %s", k, v)
		}
	}

	return client.Do(req)
}

func TestSmokescreenIntegration(t *testing.T) {
	var logHook logrustest.Hook

	// Holds TLS and non-TLS enabled local HTTP servers
	httpServers := map[bool]*httptest.Server{}
	mitmHttpServers := map[bool]*httptest.Server{} // For MITM tests

	// Holds TLS and non-TLS enabled Smokescreen instances
	proxyServers := map[bool]*httptest.Server{}

	// Contains http and https URLs to api.github.com
	externalHosts := make(map[bool]string)

	for _, useTLS := range []bool{true, false} {
		// Smokescreen instances
		_, proxyServer, err := startSmokescreen(t, useTLS, &logHook, "")
		require.NoError(t, err)
		defer proxyServer.Close()
		proxyServers[useTLS] = proxyServer

		if useTLS {
			externalHosts[useTLS] = "https://api.stripe.com:443"

			httpServer := httptest.NewTLSServer(ProxyTargetHandler)
			defer httpServer.Close()
			httpServers[useTLS] = httpServer

			mitmServer := httptest.NewTLSServer(mitmReflectingHandler)
			defer mitmServer.Close()
			mitmHttpServers[useTLS] = mitmServer
		} else {
			// Must specify a domain which won't redirect to HTTPS
			externalHosts[useTLS] = "http://checkip.amazonaws.com:80"

			httpServer := httptest.NewServer(ProxyTargetHandler)
			defer httpServer.Close()
			httpServers[useTLS] = httpServer

			mitmServer := httptest.NewServer(mitmReflectingHandler)
			defer mitmServer.Close()
			mitmHttpServers[useTLS] = mitmServer
		}
	}

	// Send the proxy request via TLS
	overTLSOptions := []bool{true, false}

	// Send the proxy request using CONNECT
	overConnectOptions := []bool{true, false}

	// If the proxy target should be sent to an authorized host
	authorizedHosts := []bool{true, false}

	enforcementPolicies := []acl.EnforcementPolicy{
		acl.Enforce,
		acl.Report,
		acl.Open,
	}

	var testCases []*TestCase

	// This generates all the permutations for the common test cases
	// * proxy requests using CONNECT and regular HTTP proxy
	// * TLS and non-TLS proxy targets
	// * hosts authorized and not authorized by the config in testdata/sample_config.yaml
	// * enforce, report, and open enforcement policies
	for _, overConnect := range overConnectOptions {
		for _, overTLS := range overTLSOptions {
			// Explicitly do not support these test cases
			// 1) You cannot tunnel TLS using a traditional HTTP proxy request
			// 2) If you attempt to tunnel a non-TLS HTTP request using CONNECT,
			//    Go's HTTP machinery rewrites the scheme as HTTPS.
			if (overTLS && !overConnect) || (!overTLS && overConnect) {
				continue
			}

			// An authorizedHost indicates the request should be sent to our
			// local HTTP server. If authorizedHost is false, the request
			// will be sent to api.github.com and may or may not be allowed
			// depending on the acl.EnforcementPolicy.
			for _, authorizedHost := range authorizedHosts {
				var proxyTarget string
				if authorizedHost {
					proxyTarget = httpServers[overTLS].URL
				} else {
					proxyTarget = externalHosts[overTLS]
				}

				for _, policy := range enforcementPolicies {
					var expectAllow bool
					// If a host is authorized, it is allowed by the config
					// and will always be allowed.
					if authorizedHost {
						expectAllow = true
					}

					// Report and open modes should always allow requests.
					if policy != acl.Enforce {
						expectAllow = true
						if policy == acl.Open {
							expectedLogReason = "rule has open enforcement policy"
						} else if policy == acl.Report { // acl.Report
							expectedLogReason = "rule has report policy"
						}
					} else { // acl.Enforce
						if authorizedHost {
							expectedLogReason = "host matched allowed domain in rule"
						} else {
							if overConnect {
								expectedLogReason = "connect proxy host not allowed in rule"
							} else {
								expectedLogReason = "host did not match any allowed domain"
							}
						}
					}


					testCase := &TestCase{
						ExpectAllow: expectAllow,
						Action:      policy,
						OverTLS:     overTLS,
						OverConnect: overConnect,
						ProxyURL:    proxyServers[overTLS].URL,
						TargetURL:   proxyTarget,
						RoleName:    generateRoleForPolicy(policy),
						ExpectedLogProject: "test", // Default project for these roles
						ExpectedLogReason: expectedLogReason,
					}

					if expectAllow {
						testCase.ExpectStatus = http.StatusOK
						if overTLS && !authorizedHost {
							// The Stripe API returns a 404 to a bare HTTP GET request
							testCase.ExpectStatus = http.StatusNotFound
						}
					} else {
						testCase.ExpectStatus = http.StatusProxyAuthRequired
					}
					testCases = append(testCases, testCase)
				}
			}
		}

		baseCase := TestCase{
			OverTLS:     false,
			OverConnect: overConnect,
			ProxyURL:    proxyServers[false].URL,
		}

		// Empty roles should default deny per the test config
		noRoleDenyCase := baseCase
		noRoleDenyCase.TargetURL = httpServers[baseCase.OverTLS].URL
		noRoleDenyCase.ExpectAllow = false
		noRoleDenyCase.ExpectStatus = http.StatusProxyAuthRequired
		noRoleDenyCase.ExpectedLogProject = "security"
		noRoleDenyCase.ExpectedLogReason = "default rule policy used"


		// Unknown roles should default deny per the test config
		unknownRoleDenyCase := baseCase
		unknownRoleDenyCase.TargetURL = httpServers[baseCase.OverTLS].URL
		unknownRoleDenyCase.RoleName = "unknown"
		unknownRoleDenyCase.ExpectAllow = false
		unknownRoleDenyCase.ExpectStatus = http.StatusProxyAuthRequired
		unknownRoleDenyCase.ExpectedLogProject = "security"
		unknownRoleDenyCase.ExpectedLogReason = "default rule policy used"

		// This must be a global unicast, non-loopback address or other IP rules will
		// block it regardless of the specific configuration we're trying to test.
		badIPRangeCase := baseCase
		badIPRangeCase.TargetURL = "http://1.1.1.1:80" // Denied by --deny-range=1.1.1.1/32
		badIPRangeCase.ExpectAllow = false
		badIPRangeCase.ExpectStatus = http.StatusProxyAuthRequired
		badIPRangeCase.RoleName = generateRoleForPolicy(acl.Open) // Role is open but IP deny takes precedence
		badIPRangeCase.ExpectedLogProject = "test"                // Project of the 'open' role
		badIPRangeCase.ExpectedLogReason = "was denied by rule 'Deny: User Configured'"


		// This must be a global unicast, non-loopback address or other IP rules will
		// block it regardless of the specific configuration we're trying to test.
		badIPAddressCase := baseCase
		badIPAddressCase.TargetURL = "http://1.0.0.1:123" // Denied by --deny-address=1.0.0.1:123
		badIPAddressCase.ExpectAllow = false
		badIPAddressCase.ExpectStatus = http.StatusProxyAuthRequired
		badIPAddressCase.RoleName = generateRoleForPolicy(acl.Open) // Role is open but IP deny takes precedence
		badIPAddressCase.ExpectedLogProject = "test"                // Project of the 'open' role
		badIPAddressCase.ExpectedLogReason = "was denied by rule 'Deny: User Configured'"


		testCases = append(testCases,
			&unknownRoleDenyCase, &noRoleDenyCase,
			&badIPRangeCase, &badIPAddressCase,
		)
	}

	// Wildcard domain test cases
	wildcardRoleName := "service-wildcard-mitm" 
	wildcardProject := "test-wildcard"

	wildcardTestCases := []*TestCase{
		{
			ExpectAllow:  true, Action: acl.Enforce, ExpectStatus: http.StatusOK, OverTLS: false, OverConnect:  false,
			ProxyURL:     proxyServers[false].URL, TargetURL:    fmt.Sprintf("http://sub.wildcard.test:%s", getPort(httpServers[false].URL)), 
			RoleName:     wildcardRoleName, ShouldNotHaveDetailedLogs: true, MitmConfiguredHeaderKey: "",     
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host matched allowed domain in rule",
		},
		{
			ExpectAllow:  true, Action: acl.Enforce, ExpectStatus: http.StatusOK, OverTLS: false, OverConnect:  false,
			ProxyURL:     proxyServers[false].URL, TargetURL:    fmt.Sprintf("http://deep.sub.wildcard.test:%s", getPort(httpServers[false].URL)), 
			RoleName:     wildcardRoleName, ShouldNotHaveDetailedLogs: true, MitmConfiguredHeaderKey: "",     
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host matched allowed domain in rule",
		},
		{
			ExpectAllow:  false, Action: acl.Enforce, ExpectStatus: http.StatusProxyAuthRequired, OverTLS: false, OverConnect:  false,
			ProxyURL:     proxyServers[false].URL, TargetURL:    fmt.Sprintf("http://wildcard.test:%s", getPort(httpServers[false].URL)), 
			RoleName:     wildcardRoleName, MitmConfiguredHeaderKey: "", 
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host did not match any allowed domain",
		},
		{
			ExpectAllow:  false, Action: acl.Enforce, ExpectStatus: http.StatusProxyAuthRequired, OverTLS: false, OverConnect:  false,
			ProxyURL:     proxyServers[false].URL, TargetURL:    fmt.Sprintf("http://foo.anotherdomain.test:%s", getPort(httpServers[false].URL)), 
			RoleName:     wildcardRoleName, MitmConfiguredHeaderKey: "", 
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host did not match any allowed domain",
		},
		{
			ExpectAllow:  true, Action: acl.Enforce, ExpectStatus: http.StatusOK, OverTLS: false, OverConnect:  false,
			ProxyURL:     proxyServers[false].URL, TargetURL:    fmt.Sprintf("http://specific.wildcard.test:%s", getPort(httpServers[false].URL)), 
			RoleName:     wildcardRoleName, ExpectDetailedLogs: true, MitmConfiguredHeaderKey: "X-Mitm-Test", 
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host matched allowed domain in rule",
		},
		{
			ExpectAllow:  true, Action: acl.Enforce, ExpectStatus: http.StatusOK, OverTLS: true, OverConnect:  true,
			ProxyURL:     proxyServers[true].URL, TargetURL:    fmt.Sprintf("https://sub.wildcard.test:%s", getPort(httpServers[true].URL)), 
			RoleName:     wildcardRoleName, ShouldNotHaveDetailedLogs: true, MitmConfiguredHeaderKey: "",     
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host matched allowed domain in rule",
		},
		{
			ExpectAllow:  true, Action: acl.Enforce, ExpectStatus: http.StatusOK, OverTLS: true, OverConnect:  true,
			ProxyURL:     proxyServers[true].URL, TargetURL:    fmt.Sprintf("https://deep.sub.wildcard.test:%s", getPort(httpServers[true].URL)), 
			RoleName:     wildcardRoleName, ShouldNotHaveDetailedLogs: true, MitmConfiguredHeaderKey: "",     
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host matched allowed domain in rule",
		},
		{
			ExpectAllow:  false, Action: acl.Enforce, ExpectStatus: http.StatusProxyAuthRequired, OverTLS: true, OverConnect:  true,
			ProxyURL:     proxyServers[true].URL, TargetURL:    fmt.Sprintf("https://wildcard.test:%s", getPort(httpServers[true].URL)), 
			RoleName:     wildcardRoleName, MitmConfiguredHeaderKey: "", 
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "connect proxy host not allowed in rule",
		},
		{
			ExpectAllow:  false, Action: acl.Enforce, ExpectStatus: http.StatusProxyAuthRequired, OverTLS: true, OverConnect:  true,
			ProxyURL:     proxyServers[true].URL, TargetURL:    fmt.Sprintf("https://foo.anotherdomain.test:%s", getPort(httpServers[true].URL)), 
			RoleName:     wildcardRoleName, MitmConfiguredHeaderKey: "", 
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "connect proxy host not allowed in rule",
		},
		{
			ExpectAllow:  true, Action: acl.Enforce, ExpectStatus: http.StatusOK, OverTLS: true, OverConnect:  true,
			ProxyURL:     proxyServers[true].URL, TargetURL:    fmt.Sprintf("https://specific.wildcard.test:%s", getPort(httpServers[true].URL)), 
			RoleName:     wildcardRoleName, ExpectDetailedLogs: true, MitmConfiguredHeaderKey: "X-Mitm-Test", 
			ExpectedLogProject: wildcardProject, ExpectedLogReason: "host matched allowed domain in rule",
		},
	}
	testCases = append(testCases, wildcardTestCases...)

	// MITM Test Cases
	mitmTestCases := []*TestCase{
		// --- Test for specific.wildcard.test (detailed_http_logs: true, X-Mitm-Test: Value1) ---
		// HTTP Proxy (non-TLS proxy, non-TLS target)
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           false,
			OverConnect:       false,
			ProxyURL:          proxyServers[false].URL,
			TargetURL:         fmt.Sprintf("http://specific.wildcard.test:%s", getPort(mitmHttpServers[false].URL)), // Target MITM server
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Mitm-Test": "Value1"},
			ExpectDetailedLogs: true,
			MitmConfiguredHeaderKey: "X-Mitm-Test", // Help log validation find this header
		},
		// CONNECT Proxy (TLS proxy, TLS target)
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           true,
			OverConnect:       true,
			ProxyURL:          proxyServers[true].URL,
			TargetURL:         fmt.Sprintf("https://specific.wildcard.test:%s", getPort(mitmHttpServers[true].URL)), // Target MITM server
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Mitm-Test": "Value1"},
			ExpectDetailedLogs: true,
			MitmConfiguredHeaderKey: "X-Mitm-Test",
		},

		// --- Test for another.specific.wildcard.test (detailed_http_logs: false, X-Another-Mitm: Value2) ---
		// HTTP Proxy
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           false,
			OverConnect:       false,
			ProxyURL:          proxyServers[false].URL,
			TargetURL:         fmt.Sprintf("http://another.specific.wildcard.test:%s", getPort(mitmHttpServers[false].URL)),
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Another-Mitm": "Value2"},
			// detailed_http_logs is false for this domain in the config.
			// So, we should NOT find evidence of *detailed* logging (like X-Another-Mitm in log fields).
			ShouldNotHaveDetailedLogs: true,
			// However, Smokescreen *will* add the "X-Another-Mitm" header to the request sent to the upstream.
			// The MitmConfiguredHeaderKey is set to "X-Another-Mitm" to indicate this is the header we're focused on.
			// The current log check `entry.Data[test.MitmConfiguredHeaderKey] != nil` would imply that if this header
			// is found in *any* log field, `foundDetailedLogEvidence` becomes true.
			// This might conflict with `ShouldNotHaveDetailedLogs: true`.
			//
			// Let's refine the meaning of MitmConfiguredHeaderKey for ShouldNotHaveDetailedLogs.
			// If ShouldNotHaveDetailedLogs is true, then the log check should assert that
			// entry.Data[MitmConfiguredHeaderKey] is *NOT* found (or that specific detailed log messages are absent).
			// The current logic in validateProxyResponse for ShouldNotHaveDetailedLogs is:
			// `a.False(foundDetailedLogEvidence, ...)`
			// And foundDetailedLogEvidence is true if `entry.Data[test.MitmConfiguredHeaderKey] != nil`.
			// This setup is correct: we expect X-Another-Mitm NOT to be in the log fields because detailed_http_logs is false.
			MitmConfiguredHeaderKey: "X-Another-Mitm",
		},
		// CONNECT Proxy
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           true,
			OverConnect:       true,
			ProxyURL:          proxyServers[true].URL,
			TargetURL:         fmt.Sprintf("https://another.specific.wildcard.test:%s", getPort(mitmHttpServers[true].URL)),
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Another-Mitm": "Value2"},
			ShouldNotHaveDetailedLogs: true,
			MitmConfiguredHeaderKey: "X-Another-Mitm",
		},
	}
	testCases = append(testCases, mitmTestCases...)

	// External Proxy Globs Test Cases
	// These tests primarily focus on CONNECT requests (OverConnect=true, OverTLS=true)
	// as X-Upstream-Https-Proxy is most relevant there.
	extProxyRoleName := "service-ext-proxy"
	externalProxyTestCases := []*TestCase{
		// Scenario a: Allowed - Matching X-Upstream-Https-Proxy and matching allowed_domains
		{
			ExpectAllow:   true,
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusOK,
			OverTLS:       true,
			OverConnect:   true,
			ProxyURL:      proxyServers[true].URL,
			TargetURL:     fmt.Sprintf("https://proxied.target.test:%s", getPort(httpServers[true].URL)),
			RoleName:      extProxyRoleName,
			HeaderToAdd:   map[string]string{"X-Upstream-Https-Proxy": "https://foo.externalproxy.com:8443"},
		},
		// Scenario b: Denied (External Proxy Mismatch) - Non-matching X-Upstream-Https-Proxy, matching allowed_domains
		{
			ExpectAllow:   false,
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusProxyAuthRequired,
			OverTLS:       true,
			OverConnect:   true,
			ProxyURL:      proxyServers[true].URL,
			TargetURL:     fmt.Sprintf("https://proxied.target.test:%s", getPort(httpServers[true].URL)),
			RoleName:      extProxyRoleName,
			HeaderToAdd:   map[string]string{"X-Upstream-Https-Proxy": "https://foo.anotherproxy.org:8443"},
		},
		// Scenario c: Denied (Domain Mismatch) - Matching X-Upstream-Https-Proxy, non-matching allowed_domains
		{
			ExpectAllow:   false,
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusProxyAuthRequired,
			OverTLS:       true,
			OverConnect:   true,
			ProxyURL:      proxyServers[true].URL,
			TargetURL:     fmt.Sprintf("https://another.target.net:%s", getPort(httpServers[true].URL)), // Non-allowed domain
			RoleName:      extProxyRoleName,
			HeaderToAdd:   map[string]string{"X-Upstream-Https-Proxy": "https://foo.externalproxy.com:8443"},
		},
		// Scenario d: Allowed (No Header) - No X-Upstream-Https-Proxy header, matching allowed_domains
		{
			ExpectAllow:   true,
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusOK,
			OverTLS:       true,
			OverConnect:   true,
			ProxyURL:      proxyServers[true].URL,
			TargetURL:     fmt.Sprintf("https://proxied.target.test:%s", getPort(httpServers[true].URL)),
			RoleName:      extProxyRoleName,
			HeaderToAdd:   nil, // No extra header
		},
		// Additional test: Denied (No Header, domain mismatch) - To ensure baseline domain check still works
		{
			ExpectAllow:   false,
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusProxyAuthRequired,
			OverTLS:       true,
			OverConnect:   true,
			ProxyURL:      proxyServers[true].URL,
			TargetURL:     fmt.Sprintf("https://another.target.net:%s", getPort(httpServers[true].URL)), // Non-allowed domain
			RoleName:      extProxyRoleName,
			HeaderToAdd:   nil,
		},
		// Additional test: Non-CONNECT, HTTP, with X-Upstream-Https-Proxy (behavior might be undefined by Smokescreen, but ACL should still deny if proxy glob mismatches)
		// Smokescreen's current ACL logic for ExternalProxyGlobs applies regardless of CONNECT, if the header is present.
		{
			ExpectAllow:   false, // Denied due to ext proxy glob mismatch for the role
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusProxyAuthRequired,
			OverTLS:       false, // HTTP proxy
			OverConnect:   false, // Not a CONNECT request
			ProxyURL:      proxyServers[false].URL,
			TargetURL:     fmt.Sprintf("http://proxied.target.test:%s", getPort(httpServers[false].URL)),
			RoleName:      extProxyRoleName,
			HeaderToAdd:   map[string]string{"X-Upstream-Https-Proxy": "https://foo.anotherproxy.org:8080"},
		},
		// Additional test: Non-CONNECT, HTTP, with matching X-Upstream-Https-Proxy
		{
			ExpectAllow:   true, // Allowed as domain and ext proxy glob match
			Action:        acl.Enforce,
			ExpectStatus:  http.StatusOK,
			OverTLS:       false, // HTTP proxy
			OverConnect:   false, // Not a CONNECT request
			ProxyURL:      proxyServers[false].URL,
			TargetURL:     fmt.Sprintf("http://proxied.target.test:%s", getPort(httpServers[false].URL)),
			RoleName:      extProxyRoleName,
			HeaderToAdd:   map[string]string{"X-Upstream-Https-Proxy": "https://bar.externalproxy.com:8080"},
		},
	}
	testCases = append(testCases, externalProxyTestCases...)

	// Global Allow/Deny List Test Cases
	globalListTestCases := []*TestCase{}

	// --- Test Scenarios for GlobalDenyList ---
	roleGlobalDeny := "service-global-deny-test" // action: open

	// Scenario a: Denied by global_deny_list (direct match), role is open
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   false,
		Action:        acl.Open, // Role's action
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://globally.denied.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalDeny,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   false,
		Action:        acl.Open,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://globally.denied.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalDeny,
	})

	// Scenario b: Denied by global_deny_list (wildcard match), role is open
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   false,
		Action:        acl.Open,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://foo.sub.denied.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalDeny,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   false,
		Action:        acl.Open,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://foo.sub.denied.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalDeny,
	})

	// Scenario c: Denied by global_deny_list even if in role's allowed_domains (role is open, so allowed_domains is not strictly enforced by role itself)
	// This is effectively the same as scenario 'a' because global deny takes precedence.
	// globally.denied.com is in service-global-deny-test's allowed_domains.
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   false,
		Action:        acl.Open,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://globally.denied.com:%s", getPort(httpServers[false].URL)), // This domain is in its allowed_domains
		RoleName:      roleGlobalDeny,
	})

	// Scenario d: Allowed by open role (not on global_deny_list)
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   true,
		Action:        acl.Open,
		ExpectStatus:  http.StatusOK,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://normal.allowed.here:%s", getPort(httpServers[false].URL)), // In role's allowed_domains
		RoleName:      roleGlobalDeny,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   true,
		Action:        acl.Open,
		ExpectStatus:  http.StatusOK,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://normal.allowed.here:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalDeny,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // Another random domain for open role
		ExpectAllow:   true,
		Action:        acl.Open,
		ExpectStatus:  http.StatusOK,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://another.random.domain.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalDeny,
	})


	// --- Test Scenarios for GlobalAllowList ---
	roleGlobalAllow := "service-global-allow-test" // action: enforce, allowed_domains: ["onlythis.specificdomain.com"]

	// Scenario e: Allowed by global_allow_list (direct match), role is enforce and domain not in role's allowed_domains
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   true,
		Action:        acl.Enforce, // Role's action
		ExpectStatus:  http.StatusOK,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://globally.allowed.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalAllow,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   true,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusOK,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://globally.allowed.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalAllow,
	})

	// Scenario f: Allowed by global_allow_list (wildcard match), role is enforce and domain not in role's allowed_domains
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   true,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusOK,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://foo.sub.allowed.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalAllow,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   true,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusOK,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://foo.sub.allowed.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalAllow,
	})

	// Scenario g: Denied by enforce role (not on global_allow_list, not in role's allowed_domains)
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   false,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://another.random.domain.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalAllow,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   false,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://another.random.domain.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalAllow,
	})

	// Scenario h: Allowed by enforce role (in role's allowed_domains, not on global_allow_list but global_allow_list doesn't prevent this)
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   true,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusOK,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://onlythis.specificdomain.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalAllow,
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   true,
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusOK,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://onlythis.specificdomain.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalAllow,
	})
	
	// Scenario: Global Deny List should take precedence over Global Allow List
	// Test this by having a domain that could be on both (implicitly or explicitly).
	// Current config: globally.denied.com (deny), globally.allowed.com (allow) - no direct overlap.
	// *.sub.denied.com (deny), *.sub.allowed.com (allow) - no direct overlap for a single domain.
	// If we had deny: *.example.com, allow: foo.example.com, then foo.example.com should be denied.
	// We can test a domain that is on global_deny_list, and try to access it with a role that
	// might otherwise allow it (e.g. an "open" role, or an "enforce" role that has it in global_allow_list).
	// Since global_deny_list is checked first, it should be denied.
	// This is already covered by scenario 'a' and 'b' where the role is 'open'.
	// To make it more explicit for an 'enforce' role:
	// If 'service-global-allow-test' (enforce) tries to access 'globally.denied.com', it should be denied.
	globalListTestCases = append(globalListTestCases, &TestCase{
		ExpectAllow:   false, // Denied by global_deny_list
		Action:        acl.Enforce, // Role is service-global-allow-test
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       false, OverConnect: false, ProxyURL: proxyServers[false].URL,
		TargetURL:     fmt.Sprintf("http://globally.denied.com:%s", getPort(httpServers[false].URL)),
		RoleName:      roleGlobalAllow, // Using the 'enforce' role that has its own rules + global allow
	})
	globalListTestCases = append(globalListTestCases, &TestCase{ // CONNECT version
		ExpectAllow:   false, // Denied by global_deny_list
		Action:        acl.Enforce,
		ExpectStatus:  http.StatusProxyAuthRequired,
		OverTLS:       true, OverConnect: true, ProxyURL: proxyServers[true].URL,
		TargetURL:     fmt.Sprintf("https://globally.denied.com:%s", getPort(httpServers[true].URL)),
		RoleName:      roleGlobalAllow,
	})


	testCases = append(testCases, globalListTestCases...)

	for _, testCase := range testCases {
		var targetServerType string
		// Determine if the target URL uses a port from mitmHttpServers or httpServers for test naming
		isMitmTarget := false
		mitmPortNonTLS := getPort(mitmHttpServers[false].URL)
		mitmPortTLS := getPort(mitmHttpServers[true].URL)
		targetPort := getPort(testCase.TargetURL)

		if targetPort == mitmPortNonTLS || targetPort == mitmPortTLS {
			isMitmTarget = true
		}

		if isMitmTarget {
			targetServerType = "MitmTarget"
		} else {
			targetServerType = "StdTarget"
		}
		
		runName := fmt.Sprintf("Target_%s_Role_%s_Connect_%t_ProxyTLS_%t_ServerType_%s_DetailedLogsExpected_%t_NoDetailedLogsExpected_%t",
			testCase.TargetURL, testCase.RoleName, testCase.OverConnect,
			testCase.ProxyURL == proxyServers[true].URL, targetServerType, testCase.ExpectDetailedLogs, testCase.ShouldNotHaveDetailedLogs)

		t.Run(runName, func(t *testing.T) {
			testCase.RandomTrace = rand.Int()
			resp, err := executeRequestForTest(t, testCase, &logHook)
			validateProxyResponse(t, testCase, resp, err, logHook.AllEntries())
		})
	}
}
		// which use the mitmHttpServers. We can remove or adapt. For now, let's adapt it to be a non-MITM check
		// if we assume the MITM handler is different. Or, if it's the same handler, this is fine.
		// Given we now have mitmHttpServers, this existing test should point to httpServers.
		{
			ExpectAllow:  true, // specific.wildcard.test is explicitly allowed
			Action:       acl.Enforce,
			ExpectStatus: http.StatusOK,
			OverTLS:      false,
			OverConnect:  false,
			ProxyURL:     proxyServers[false].URL,
			TargetURL:    fmt.Sprintf("http://specific.wildcard.test:%s", getPort(httpServers[false].URL)), // Standard server
			RoleName:     wildcardRoleName,
			// This domain IS configured for MITM, so detailed logs might appear depending on Smokescreen's behavior.
			// If Smokescreen logs added headers even if the upstream doesn't see them (due to different handler),
			// then ExpectDetailedLogs might be true. For now, let's assume the log check is tied to the mitmHttpServer use.
			// This test case might become redundant or need careful thought.
			// For now, let's assume it's a baseline check that it's allowed, without specific MITM log checks.
		},

		// CONNECT Proxy (overConnect=true, overTLS=true)
		// Target: https://sub.wildcard.test:<port_from_httpServers[true]>
		// Note: For CONNECT, TargetURL in NewRequest is host:port, scheme is implicit from TLS
		{
			ExpectAllow:  true,
			Action:       acl.Enforce,
			ExpectStatus: http.StatusOK,
			OverTLS:      true,
			OverConnect:  true,
			ProxyURL:     proxyServers[true].URL, // Proxy is TLS enabled
			TargetURL:    fmt.Sprintf("https://sub.wildcard.test:%s", getPort(httpServers[true].URL)), // Standard server
			RoleName:     wildcardRoleName,
			ShouldNotHaveDetailedLogs: true, // Control: non-MITM domain for this role
		},
		{
			ExpectAllow:  true,
			Action:       acl.Enforce,
			ExpectStatus: http.StatusOK,
			OverTLS:      true,
			OverConnect:  true,
			ProxyURL:     proxyServers[true].URL,
			TargetURL:    fmt.Sprintf("https://deep.sub.wildcard.test:%s", getPort(httpServers[true].URL)), // Standard server
			RoleName:     wildcardRoleName,
			ShouldNotHaveDetailedLogs: true, // Control: non-MITM domain for this role
		},
		{
			ExpectAllow:  false, // *.wildcard.test requires at least one label
			Action:       acl.Enforce,
			ExpectStatus: http.StatusProxyAuthRequired, // Smokescreen itself will deny via CONNECT response
			OverTLS:      true,
			OverConnect:  true,
			ProxyURL:     proxyServers[true].URL,
			TargetURL:    fmt.Sprintf("https://wildcard.test:%s", getPort(httpServers[true].URL)), // Standard server
			RoleName:     wildcardRoleName,
		},
		{
			ExpectAllow:  false,
			Action:       acl.Enforce,
			ExpectStatus: http.StatusProxyAuthRequired,
			OverTLS:      true,
			OverConnect:  true,
			ProxyURL:     proxyServers[true].URL,
			TargetURL:    fmt.Sprintf("https://foo.anotherdomain.test:%s", getPort(httpServers[true].URL)), // Standard server
			RoleName:     wildcardRoleName,
		},
		// Similar to the HTTP case, this specific.wildcard.test is allowed by wildcard rules,
		// but will now also be a MITM target. This existing test should point to httpServers.
		{
			ExpectAllow:  true, // specific.wildcard.test is explicitly allowed
			Action:       acl.Enforce,
			ExpectStatus: http.StatusOK,
			OverTLS:      true,
			OverConnect:  true,
			ProxyURL:     proxyServers[true].URL,
			TargetURL:    fmt.Sprintf("https://specific.wildcard.test:%s", getPort(httpServers[true].URL)), // Standard server
			RoleName:     wildcardRoleName,
		},
	}
	testCases = append(testCases, wildcardTestCases...)

	// MITM Test Cases
	mitmTestCases := []*TestCase{
		// --- Test for specific.wildcard.test (detailed_http_logs: true, X-Mitm-Test: Value1) ---
		// HTTP Proxy (non-TLS proxy, non-TLS target)
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           false,
			OverConnect:       false,
			ProxyURL:          proxyServers[false].URL,
			TargetURL:         fmt.Sprintf("http://specific.wildcard.test:%s", getPort(mitmHttpServers[false].URL)), // Target MITM server
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Mitm-Test": "Value1"},
			ExpectDetailedLogs: true,
			MitmConfiguredHeaderKey: "X-Mitm-Test", // Help log validation find this header
		},
		// CONNECT Proxy (TLS proxy, TLS target)
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           true,
			OverConnect:       true,
			ProxyURL:          proxyServers[true].URL,
			TargetURL:         fmt.Sprintf("https://specific.wildcard.test:%s", getPort(mitmHttpServers[true].URL)), // Target MITM server
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Mitm-Test": "Value1"},
			ExpectDetailedLogs: true,
			MitmConfiguredHeaderKey: "X-Mitm-Test",
		},

		// --- Test for another.specific.wildcard.test (detailed_http_logs: false, X-Another-Mitm: Value2) ---
		// HTTP Proxy
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           false,
			OverConnect:       false,
			ProxyURL:          proxyServers[false].URL,
			TargetURL:         fmt.Sprintf("http://another.specific.wildcard.test:%s", getPort(mitmHttpServers[false].URL)),
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Another-Mitm": "Value2"},
			ShouldNotHaveDetailedLogs: true, // Detailed logs are false for this one
			MitmConfiguredHeaderKey: "X-Another-Mitm", // Still, Smokescreen might log the header it adds.
		},
		// CONNECT Proxy
		{
			ExpectAllow:       true,
			Action:            acl.Enforce,
			ExpectStatus:      http.StatusOK,
			OverTLS:           true,
			OverConnect:       true,
			ProxyURL:          proxyServers[true].URL,
			TargetURL:         fmt.Sprintf("https://another.specific.wildcard.test:%s", getPort(mitmHttpServers[true].URL)),
			RoleName:          wildcardRoleName,
			ExpectEchoHeaders: map[string]string{"Echo-X-Another-Mitm": "Value2"},
			ShouldNotHaveDetailedLogs: true,
			MitmConfiguredHeaderKey: "X-Another-Mitm",
		},
	}
	testCases = append(testCases, mitmTestCases...)

	for _, testCase := range testCases {
		var targetServerType string
		// Determine if the target URL uses a port from mitmHttpServers or httpServers for test naming
		isMitmTarget := false
		mitmPortNonTLS := getPort(mitmHttpServers[false].URL)
		mitmPortTLS := getPort(mitmHttpServers[true].URL)
		targetPort := getPort(testCase.TargetURL)

		if targetPort == mitmPortNonTLS || targetPort == mitmPortTLS {
			isMitmTarget = true
		}

		if isMitmTarget {
			targetServerType = "MitmTarget"
		} else {
			targetServerType = "StdTarget"
		}
		
		runName := fmt.Sprintf("Target_%s_Role_%s_Connect_%t_ProxyTLS_%t_ServerType_%s_DetailedLogsExpected_%t_NoDetailedLogsExpected_%t",
			testCase.TargetURL, testCase.RoleName, testCase.OverConnect,
			testCase.ProxyURL == proxyServers[true].URL, targetServerType, testCase.ExpectDetailedLogs, testCase.ShouldNotHaveDetailedLogs)

		t.Run(runName, func(t *testing.T) {
			testCase.RandomTrace = rand.Int()
			resp, err := executeRequestForTest(t, testCase, &logHook)
			validateProxyResponse(t, testCase, resp, err, logHook.AllEntries())
		})
	}
}

// validateProxyResponseWithUpstream validates tests cases and expected responses
// from TestUpstreamProxySmokescreenIntegration. This validates that requests
// sent to a smokescreen instance with an additional upstream proxy set
// (proxy chaining) forwards the request to the next proxy hop instead of directly
// to the proxy target.
func validateProxyResponseWithUpstream(t *testing.T, test *TestCase, resp *http.Response, err error, logs []*logrus.Entry) {
	a := assert.New(t)
	t.Logf("HTTP Response: %#v", resp)

	if test.OverConnect {
		a.Contains(err.Error(), "Failed to resolve remote hostname")
	} else {
		a.Equal(http.StatusBadGateway, resp.StatusCode)
	}
}

// This test must be run with a separate test command as the environment variables
// required can race with the test above.
func TestInvalidUpstreamProxyConfiguratedFromEnv(t *testing.T) {
	var logHook logrustest.Hook
	servers := map[bool]*httptest.Server{}

	// Create TLS and non-TLS instances of Smokescreen
	for _, useTLS := range []bool{true, false} {
		_, server, err := startSmokescreen(t, useTLS, &logHook, "")
		require.NoError(t, err)
		defer server.Close()
		servers[useTLS] = server
	}

	// Passing an illegal upstream proxy value is not designed to be an especially well
	// handled error so it would fail many of the checks in our other tests. We really
	// only care to ensure that these requests never succeed.
	for _, overConnect := range []bool{true, false} {
		t.Run(fmt.Sprintf("illegal proxy with CONNECT %t", overConnect), func(t *testing.T) {
			var proxyTarget string
			var upstreamProxy string

			// These proxy targets don't actually matter as the requests won't be sent.
			// because the resolution of the upstream proxy will fail.
			if overConnect {
				upstreamProxy = "https://notaproxy.prxy.svc:443"
				proxyTarget = "https://api.stripe.com:443"
			} else {
				upstreamProxy = "http://notaproxy.prxy.svc:80"
				proxyTarget = "http://checkip.amazonaws.com:80"
			}

			testCase := &TestCase{
				OverConnect:   overConnect,
				OverTLS:       overConnect,
				ProxyURL:      servers[overConnect].URL,
				TargetURL:     proxyTarget,
				UpstreamProxy: upstreamProxy,
				RoleName:      generateRoleForPolicy(acl.Open),
				ExpectStatus:  http.StatusBadGateway,
			}
			os.Setenv("http_proxy", testCase.UpstreamProxy)
			os.Setenv("https_proxy", testCase.UpstreamProxy)

			resp, err := executeRequestForTest(t, testCase, &logHook)
			validateProxyResponseWithUpstream(t, testCase, resp, err, logHook.AllEntries())

			os.Unsetenv("http_proxy")
			os.Unsetenv("https_proxy")
		})
	}
}

func TestInvalidUpstreamProxyConfiguration(t *testing.T) {
	var logHook logrustest.Hook
	servers := map[bool]*httptest.Server{}

	// Create TLS and non-TLS instances of Smokescreen
	for _, useTLS := range []bool{true, false} {
		var httpProxyAddr string
		if useTLS {
			httpProxyAddr = "https://notaproxy.prxy.svc:443"
		} else {
			httpProxyAddr = "http://notaproxy.prxy.svc:80"
		}
		_, server, err := startSmokescreen(t, useTLS, &logHook, httpProxyAddr)
		require.NoError(t, err)
		defer server.Close()
		servers[useTLS] = server
	}

	// Passing an illegal upstream proxy value is not designed to be an especially well
	// handled error so it would fail many of the checks in our other tests. We really
	// only care to ensure that these requests never succeed.
	for _, overConnect := range []bool{true, false} {
		t.Run(fmt.Sprintf("illegal proxy with CONNECT %t", overConnect), func(t *testing.T) {
			var proxyTarget string
			var upstreamProxy string

			// These proxy targets don't actually matter as the requests won't be sent.
			// because the resolution of the upstream proxy will fail.
			if overConnect {
				upstreamProxy = "https://notaproxy.prxy.svc:443"
				proxyTarget = "https://api.stripe.com:443"
			} else {
				upstreamProxy = "http://notaproxy.prxy.svc:80"
				proxyTarget = "http://checkip.amazonaws.com:80"
			}

			testCase := &TestCase{
				OverConnect:   overConnect,
				OverTLS:       overConnect,
				ProxyURL:      servers[overConnect].URL,
				TargetURL:     proxyTarget,
				UpstreamProxy: upstreamProxy,
				RoleName:      generateRoleForPolicy(acl.Open),
				ExpectStatus:  http.StatusBadGateway,
			}
			resp, err := executeRequestForTest(t, testCase, &logHook)
			validateProxyResponseWithUpstream(t, testCase, resp, err, logHook.AllEntries())

		})
	}
}

func TestClientHalfCloseConnection(t *testing.T) {
	a := assert.New(t)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "TCP is great!")
	})
	remote := httptest.NewServer(h)

	var logHook logrustest.Hook

	conf, server, err := startSmokescreen(t, false, &logHook, "")
	require.NoError(t, err)
	defer server.Close()

	proxyCon, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Error(err)
	}

	// Send the CONNECT request to Smokescreen
	conReq, err := http.NewRequest("CONNECT", remote.URL, nil)
	if err != nil {
		t.Error(err)
	}
	conReq.Header.Add("X-Smokescreen-Role", "egressneedingservice-open")
	if err := conReq.Write(proxyCon); err != nil {
		t.Error(err)
	}

	buf := bufio.NewReader(proxyCon)
	resp, err := http.ReadResponse(buf, conReq)
	if err != nil {
		t.Error(err)
	}

	a.Equal(resp.StatusCode, http.StatusOK)

	// Send the response to the "remote" server
	req, err := http.NewRequest("GET", remote.URL, nil)
	if err != nil {
		t.Error(err)
	}
	if err := req.Write(proxyCon); err != nil {
		t.Error(err)
	}
	resp, err = http.ReadResponse(buf, req)
	if err != nil {
		t.Error(err)
	}
	a.Equal(resp.StatusCode, http.StatusOK)

	// Unwrap the underlying net.TCPConn
	tcpConn, ok := proxyCon.(*net.TCPConn)
	if !ok {
		t.Error("conn did not unwrap to net.TCPConn")
	}

	// Now half close the connection and check that Smokescreen
	// logged a connection close event
	tcpConn.CloseWrite()

	conf.ConnTracker.Wg().Wait()

	entries := logHook.AllEntries()
	entry := findLogEntry(entries, "CANONICAL-PROXY-CN-CLOSE")
	a.NotNil(entry)
}

func findLogEntry(entries []*logrus.Entry, msg string) *logrus.Entry {
	for _, entry := range entries {
		if entry.Message == msg {
			return entry
		}
	}
	return nil
}

func startSmokescreen(t *testing.T, useTLS bool, logHook logrus.Hook, httpProxyAddr string) (*smokescreen.Config, *httptest.Server, error) {
	args := []string{
		"smokescreen",
		"--listen-ip=127.0.0.1",
		"--egress-acl-file=testdata/sample_config.yaml",
		"--additional-error-message-on-deny=additional_error_message_validation_key",
		"--deny-range=1.1.1.1/32",
		"--allow-range=127.0.0.1/32",
		"--deny-address=1.0.0.1:123",
	}

	if useTLS {
		args = append(args,
			"--tls-server-bundle-file=testdata/pki/server-bundle.pem",
			"--tls-client-ca-file=testdata/pki/ca.pem",
			"--tls-crl-file=testdata/pki/crl.pem",
		)
	}

	if httpProxyAddr != ""{
		args = append(args, fmt.Sprintf("--upstream-http-proxy-addr=%s", httpProxyAddr))
		args = append(args, fmt.Sprintf("--upstream-https-proxy-addr=%s", httpProxyAddr))
	}

	conf, err := NewConfiguration(args, nil)
	if err != nil {
		t.Fatalf("Failed to create configuration: %v", err)
	}

	if useTLS {
		conf.RoleFromRequest = testRFRCert
	} else {
		conf.RoleFromRequest = testRFRHeader
	}

	conf.MetricsClient = metrics.NewNoOpMetricsClient()

	conf.ConnectTimeout = time.Second

	fmt.Printf("2 %#v\n", conf)
	conf.Log.AddHook(logHook)

	handler := smokescreen.BuildProxy(conf)
	server := httptest.NewUnstartedServer(handler)

	if useTLS {
		server.TLS = conf.TlsConfig
		server.StartTLS()
	} else {
		server.Start()
	}

	return conf, server, nil
}

func getPort(serverURL string) string {
	parsedURL, _ := url.Parse(serverURL)
	return parsedURL.Port()
}

func TestInvalidACLConfigs(t *testing.T) {
	runACLValidationTest := func(t *testing.T, aclContent string, expectedErrorMsgSubstring string) {
		tmpDir := t.TempDir()
		aclFilePath := filepath.Join(tmpDir, "invalid_acl.yaml")
		require.NoError(t, ioutil.WriteFile(aclFilePath, []byte(aclContent), 0644))

		// Minimal args needed to trigger ACL loading.
		// Listen IP and port are not strictly necessary if we only load config,
		// but NewConfiguration might have checks for them.
		// Using dummy values.
		args := []string{
			"smokescreen",
			"--listen-ip=127.0.0.1",
			"--listen-port=0", // Use port 0 for OS to pick a free port if it tries to listen
			"--egress-acl-file=" + aclFilePath,
		}

		// We are testing NewConfiguration from the cmd package.
		// This function sets up the SmokescreenConfig, including loading the ACL.
		_, err := NewConfiguration(args, nil)

		require.Error(t, err, "Expected NewConfiguration to fail for this ACL content")
		if expectedErrorMsgSubstring != "" {
			assert.Contains(t, err.Error(), expectedErrorMsgSubstring, "Error message mismatch")
		}
	}

	t.Run("glob_wildcard_not_prefix_segment", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-invalid-glob
    project: test
    action: open
    allowed_domains:
      - "*foo.com"
`
		// Error from pkg/smokescreen/acl/acl.go -> normalizeDomain -> Validate
		// The actual error is "glob forms are only supported for prefix matching (e.g. *.example.com)"
		// but it gets wrapped. Let's check for a core part.
		runACLValidationTest(t, aclContent, "glob forms are only supported for prefix matching")
	})

	t.Run("glob_wildcard_internal_segment", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-invalid-glob
    project: test
    action: open
    allowed_domains:
      - "foo.*.com"
`
		// Error from pkg/smokescreen/acl/acl.go -> normalizeDomain -> Validate
		runACLValidationTest(t, aclContent, "glob forms are only supported for prefix matching")
	})

	t.Run("glob_wildcard_match_all", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-invalid-glob
    project: test
    action: open
    allowed_domains:
      - "*"
`
		// Error from pkg/smokescreen/acl/acl.go -> normalizeDomain -> Validate
		runACLValidationTest(t, aclContent, "glob must not match everything")
	})

	t.Run("glob_wildcard_match_all_dot", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-invalid-glob
    project: test
    action: open
    allowed_domains:
      - "*."
`
		// Error from pkg/smokescreen/acl/acl.go -> normalizeDomain -> Validate
		runACLValidationTest(t, aclContent, "glob must not match everything")
	})

	t.Run("glob_empty_string", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-invalid-glob
    project: test
    action: open
    allowed_domains:
      - ""
`
		// Error from pkg/smokescreen/acl/acl.go -> normalizeDomain -> Validate
		runACLValidationTest(t, aclContent, "glob cannot be empty")
	})

	// Domain Normalization Scenarios
	t.Run("normalization_domain_with_caps", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-normalization
    project: test
    action: open
    allowed_domains:
      - "DomainWithCaps.com"
`
		// This error comes from config.go's SetupEgressAcl, which calls acl.Validate()
		// acl.Validate() itself calls hostport.NormalizeHost and compares.
		runACLValidationTest(t, aclContent, "incorrect ACL entry 'DomainWithCaps.com'; use 'domainwithcaps.com'")
	})

	t.Run("normalization_unicode_domain", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-normalization
    project: test
    action: open
    allowed_domains:
      - "bücher.example.com"
`
		// Similar to above, this comes from acl.Validate() via hostport.NormalizeHost comparison.
		runACLValidationTest(t, aclContent, "incorrect ACL entry 'bücher.example.com'; use 'xn--bcher-kva.example.com'")
	})

	// Test a valid glob to ensure the helper and basic setup is fine
	t.Run("valid_glob_sanity_check", func(t *testing.T) {
		aclContent := `
version: v1
services:
  - name: test-valid-glob
    project: test
    action: open
    allowed_domains:
      - "*.example.com"
`
		tmpDir := t.TempDir()
		aclFilePath := filepath.Join(tmpDir, "valid_acl.yaml")
		require.NoError(t, ioutil.WriteFile(aclFilePath, []byte(aclContent), 0644))

		args := []string{
			"smokescreen",
			"--listen-ip=127.0.0.1",
			"--listen-port=0",
			"--egress-acl-file=" + aclFilePath,
		}
		_, err := NewConfiguration(args, nil)
		require.NoError(t, err, "Expected NewConfiguration to succeed for a valid glob")
	})
}

var echoServerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// For CONNECT requests, r.URL.Path is empty, and r.URL.RawQuery is empty.
	// The original path and query are in r.RequestURI.
	// However, after the CONNECT tunnel is established, the client sends a new HTTP request
	// through the tunnel, and *that* request will have the correct Path and RawQuery.
	// So, for the echo server, r.URL.Path and r.URL.RawQuery should be correct for the
	// request that comes *through* the tunnel.

	path := r.URL.Path
	rawQuery := r.URL.RawQuery
	host := r.Host
	method := r.Method

	// Read body for POST/PUT etc.
	var bodyStr string
	if r.Body != nil {
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err == nil {
			bodyStr = string(bodyBytes)
		}
		defer r.Body.Close()
	}

	// Using a simple string format for easy substring matching.
	// Using distinct prefixes like "Path::", "Query::" to avoid accidental matches.
	responseBody := fmt.Sprintf(
		"Method::%s Path::%s Query::%s Host::%s Body::%s",
		method, path, rawQuery, host, bodyStr,
	)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, responseBody)
})


func TestPathQueryForwarding(t *testing.T) {
	var logHook logrustest.Hook
	proxyServers := make(map[bool]*httptest.Server)

	httpEchoServer := httptest.NewServer(echoServerHandler)
	defer httpEchoServer.Close()
	t.Logf("HTTP Echo server listening on: %s", httpEchoServer.URL)

	httpsEchoServer := httptest.NewTLSServer(echoServerHandler)
	defer httpsEchoServer.Close()
	t.Logf("HTTPS Echo server listening on: %s", httpsEchoServer.URL)


	// Start Smokescreen instances (TLS and non-TLS)
	// Only non-TLS proxy is strictly needed for these tests, but setting up both is fine.
	for _, useTLS := range []bool{false, true} {
		_, proxyServer, err := startSmokescreen(t, useTLS, &logHook, "")
		require.NoError(t, err)
		defer proxyServer.Close()
		proxyServers[useTLS] = proxyServer
	}

	echoRole := "role-echo-test"
	echoProject := "test-forwarding"

	parsedHTTPURL, _ := url.Parse(httpEchoServer.URL)
	httpEchoServerHostPort := parsedHTTPURL.Host

	parsedHTTPSURL, _ := url.Parse(httpsEchoServer.URL)
	httpsEchoServerHostPort := parsedHTTPSURL.Host


	pathQueryTestCases := []TestCase{
		// Scenario a: HTTP Proxy - Simple Path & Query
		{
			RoleName:      echoRole,
			TargetURL:     httpEchoServer.URL + "/path1?queryA=valA",
			Method:        "GET",
			OverConnect:   false, OverTLS: false, ProxyURL: proxyServers[false].URL,
			ExpectAllow:   true, ExpectStatus:  http.StatusOK,
			ExpectedLogProject: echoProject, ExpectedLogReason: "rule has open enforcement policy",
			ExpectedResponseBodyContains: []string{
				"Method::GET", 
				"Path::/path1", 
				"Query::queryA=valA",
				"Host::" + httpEchoServerHostPort, // Host header will be the echo server's host:port
			},
		},
		// Scenario b: HTTP Proxy - No Query, Complex Path
		{
			RoleName:      echoRole,
			TargetURL:     httpEchoServer.URL + "/some/deep/path%20with%20spaces",
			Method:        "GET",
			OverConnect:   false, OverTLS: false, ProxyURL: proxyServers[false].URL,
			ExpectAllow:   true, ExpectStatus:  http.StatusOK,
			ExpectedLogProject: echoProject, ExpectedLogReason: "rule has open enforcement policy",
			ExpectedResponseBodyContains: []string{
				"Method::GET",
				"Path::/some/deep/path%20with%20spaces",
				"Query::", // Empty query
				"Host::" + httpEchoServerHostPort,
			},
		},
		// Scenario c: HTTP Proxy - POST with Path & Query & Body
		{
			RoleName:      echoRole,
			TargetURL:     httpEchoServer.URL + "/postpath?postQuery=1",
			Method:        "POST",
			RequestBody:   "post_body_content",
			OverConnect:   false, OverTLS: false, ProxyURL: proxyServers[false].URL,
			ExpectAllow:   true, ExpectStatus:  http.StatusOK,
			ExpectedLogProject: echoProject, ExpectedLogReason: "rule has open enforcement policy",
			ExpectedResponseBodyContains: []string{
				"Method::POST",
				"Path::/postpath",
				"Query::postQuery=1",
				"Host::" + httpEchoServerHostPort,
				"Body::post_body_content",
			},
		},
		// Scenario d: CONNECT Proxy (HTTPS) - Simple Path & Query
		{
			RoleName:      echoRole,
			TargetURL:     httpsEchoServer.URL + "/securepath?secureQ=secureA",
			Method:        "GET",
			OverConnect:   true, OverTLS: true, ProxyURL: proxyServers[true].URL,
			ExpectAllow:   true, ExpectStatus:  http.StatusOK,
			ExpectedLogProject: echoProject, ExpectedLogReason: "rule has open enforcement policy",
			ExpectedResponseBodyContains: []string{
				"Method::GET",
				"Path::/securepath",
				"Query::secureQ=secureA",
				"Host::" + httpsEchoServerHostPort, // For CONNECT, the host is the target server itself
			},
		},
		// Scenario e: CONNECT Proxy (HTTPS) - Path with Encoded Chars
		{
			RoleName:      echoRole,
			TargetURL:     httpsEchoServer.URL + "/path%2Fwith%2Fslashes?amp=%26",
			Method:        "GET",
			OverConnect:   true, OverTLS: true, ProxyURL: proxyServers[true].URL,
			ExpectAllow:   true, ExpectStatus:  http.StatusOK,
			ExpectedLogProject: echoProject, ExpectedLogReason: "rule has open enforcement policy",
			ExpectedResponseBodyContains: []string{
				"Method::GET",
				"Path::/path%2Fwith%2Fslashes", // Path should remain encoded as it's part of the resource identifier
				"Query::amp=%26",
				"Host::" + httpsEchoServerHostPort,
			},
		},
	}
	
	for _, tc := range pathQueryTestCases {
		t.Run(fmt.Sprintf("Method_%s_Target_%s_Connect_%t", tc.Method, tc.TargetURL, tc.OverConnect), func(t *testing.T) {
			tc.RandomTrace = rand.Int()
			resp, err := executeRequestForTest(t, &tc, &logHook)
			validateProxyResponse(t, &tc, resp, err, logHook.AllEntries())
		})
	}
}


func TestRedirectFollowing(t *testing.T) {
	var logHook logrustest.Hook
	proxyServers := make(map[bool]*httptest.Server)

	// Use fixed ports that match the pre-configured ACL in sample_config.yaml
	// If these ports are in use, the test might be flaky. Consider a mechanism
	// to find free ports and update ACL dynamically if this becomes an issue,
	// though that adds complexity with current tooling.
	// For now, assume these ports are available or adjust sample_config.yaml if necessary.
	const redirectingServerPort = "50001"
	const finalServerPort = "50002"

	finalServerURL := fmt.Sprintf("http://127.0.0.1:%s", finalServerPort)
	redirectingServerInitialURL := fmt.Sprintf("http://127.0.0.1:%s", redirectingServerPort)


	// Target Server (Final Destination)
	targetServerFinalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "Hello from final destination."
		queryParams := r.URL.Query()
		if len(queryParams) > 0 {
			body += " Params:"
			for k, v := range queryParams {
				body += fmt.Sprintf(" %s=%s", k, v[0]) // Taking first value for simplicity
			}
		}
		io.WriteString(w, body)
	})
	
	finalListener, err := net.Listen("tcp", "127.0.0.1:"+finalServerPort)
	require.NoError(t, err, "Failed to create listener for final server")
	targetServerFinal := httptest.NewUnstartedServer(targetServerFinalHandler)
	targetServerFinal.Listener = finalListener
	targetServerFinal.Start()
	defer targetServerFinal.Close()
	t.Logf("Final server listening on: %s", targetServerFinal.URL)


	// Redirecting Server
	targetServerRedirectingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destURL, _ := url.Parse(finalServerURL)
		// Preserve query parameters
		q := r.URL.Query()
		destURL.RawQuery = q.Encode()
		http.Redirect(w, r, destURL.String(), http.StatusMovedPermanently)
	})

	redirectingListener, err := net.Listen("tcp", "127.0.0.1:"+redirectingServerPort)
	require.NoError(t, err, "Failed to create listener for redirecting server")
	targetServerRedirecting := httptest.NewUnstartedServer(targetServerRedirectingHandler)
	targetServerRedirecting.Listener = redirectingListener
	targetServerRedirecting.Start()
	defer targetServerRedirecting.Close()
	t.Logf("Redirecting server listening on: %s", targetServerRedirecting.URL)


	// Start Smokescreen instances (TLS and non-TLS)
	for _, useTLS := range []bool{false, true} { // Only non-TLS proxy relevant for HTTP redirect tests
		if useTLS { continue } // Redirects are typically HTTP->HTTP or HTTPS->HTTPS. For this, focus on HTTP.
		_, proxyServer, err := startSmokescreen(t, useTLS, &logHook, "")
		require.NoError(t, err)
		defer proxyServer.Close()
		proxyServers[useTLS] = proxyServer
	}

	redirectTestCases := []TestCase{
		// Scenario 1: Allow-Allow
		{
			RoleName:      "role-redirect-allow-all", // action: open
			TargetURL:     targetServerRedirecting.URL + "/?param=value&foo=bar",
			ExpectAllow:   true,
			ExpectStatus:  http.StatusOK,
			OverConnect:   false, OverTLS: false, ProxyURL: proxyServers[false].URL, // Non-CONNECT GET
			ExpectedLogProject: "test-redirects",
			ExpectedLogReason:  "rule has open enforcement policy", // Final decision on final.localhost
			ExpectedResponseBodyContains: []string{"Hello from final destination", "param=value", "foo=bar"},
			ExpectedFinalQueryParams: map[string]string{"param":"value", "foo":"bar"},
		},
		// Scenario 2: Allow-Deny (Initial request to redirecting allowed, but final destination denied by role)
		// Role 'role-redirect-allow-deny' allows 127.0.0.1:50001 (redirecting) but not 127.0.0.1:50002 (final)
		{
			RoleName:      "role-redirect-allow-deny",
			TargetURL:     targetServerRedirecting.URL + "/?param=value",
			ExpectAllow:   false, // Smokescreen should block the request to the final, denied destination
			ExpectStatus:  http.StatusProxyAuthRequired, 
			OverConnect:   false, OverTLS: false, ProxyURL: proxyServers[false].URL,
			ExpectedLogProject: "test-redirects",
			// The decision reason will be for the *final* denied host.
			ExpectedLogReason:  "host did not match any allowed domain", 
		},
		// Scenario 3: Deny-Initial (Initial request to redirecting server denied)
		// Role 'role-redirect-deny-initial' does not allow 127.0.0.1:50001 (redirecting)
		{
			RoleName:      "role-redirect-deny-initial",
			TargetURL:     targetServerRedirecting.URL,
			ExpectAllow:   false,
			ExpectStatus:  http.StatusProxyAuthRequired,
			OverConnect:   false, OverTLS: false, ProxyURL: proxyServers[false].URL,
			ExpectedLogProject: "test-redirects",
			ExpectedLogReason:  "host did not match any allowed domain",
		},
	}

	for _, tc := range redirectTestCases {
		t.Run(fmt.Sprintf("Role_%s_Target_%s", tc.RoleName, tc.TargetURL), func(t *testing.T) {
			tc.RandomTrace = rand.Int()
			
			// Adjust target URLs if they were using placeholders and now have actual server URLs
			// This is tricky because tc.TargetURL is already the redirecting server.
			// The ACLs in sample_config.yaml were updated with specific ports 50001 and 50002.
			// Ensure the test servers are actually listening on these.

			resp, err := executeRequestForTest(t, &tc, &logHook)
			validateProxyResponse(t, &tc, resp, err, logHook.AllEntries())
		})
	}
}
