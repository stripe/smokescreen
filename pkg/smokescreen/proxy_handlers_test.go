//go:build !nounit
// +build !nounit

package smokescreen

import (
	"errors"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRejectResponseHandler(t *testing.T) {
	r := require.New(t)
	testHeader := "TestRejectResponseHandlerHeader"

	testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer testSrv.Close()

	t.Run("Testing custom reject response handler", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")

		// set a custom RejectResponseHandler that will set a header on every reject response
		cfg.RejectResponseHandler = func(resp *http.Response) {
			resp.Header.Set(testHeader, "This header is added by the RejectResponseHandler")
		}
		r.NoError(err)

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		// Send a request that should be blocked
		resp, err := client.Get("http://stripe.com")
		r.NoError(err)

		// The RejectResponseHandler should set our custom header
		h := resp.Header.Get(testHeader)
		if h == "" {
			t.Errorf("Expecting header %s to be set by RejectResponseHandler", testHeader)
		}
		// Send a request that should be allowed
		resp, err = client.Get(testSrv.URL)
		r.NoError(err)

		// The header set by our custom reject response handler should not be set
		h = resp.Header.Get(testHeader)
		if h != "" {
			t.Errorf("Expecting header %s to not be set by RejectResponseHandler", testHeader)
		}
	})
}

func TestRejectResponseHandlerWithCtx(t *testing.T) {
	r := require.New(t)
	testHeader := "TestRejectResponseHandlerWithCtxHeader"

	testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer testSrv.Close()

	t.Run("Testing custom reject response handler", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")

		// set a custom RejectResponseHandler that will set a header on every reject response
		cfg.RejectResponseHandlerWithCtx = func(_ *SmokescreenContext, resp *http.Response) {
			resp.Header.Set(testHeader, "This header is added by the RejectResponseHandlerWithCtx")
		}
		r.NoError(err)

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		// Send a request that should be blocked
		resp, err := client.Get("http://stripe.com")
		r.NoError(err)

		// The RejectResponseHandlerWithCtx should set our custom header
		h := resp.Header.Get(testHeader)
		if h == "" {
			t.Errorf("Expecting header %s to be set by RejectResponseHandler", testHeader)
		}
		// Send a request that should be allowed
		resp, err = client.Get(testSrv.URL)
		r.NoError(err)

		// The header set by our custom reject response handler should not be set
		h = resp.Header.Get(testHeader)
		if h != "" {
			t.Errorf("Expecting header %s to not be set by RejectResponseHandler", testHeader)
		}
	})
}

// Test that Smokescreen calls the custom accept response handler (if defined in the Config struct)
// after every accepted request
func TestAcceptResponseHandler(t *testing.T) {
	r := require.New(t)
	testHeader := "TestAcceptResponseHandlerHeader"

	testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer testSrv.Close()

	t.Run("Testing custom accept response handler", func(t *testing.T) {
		cfg, err := testConfig("test-local-srv")

		// set a custom AcceptResponseHandler that will set a header on every reject response
		cfg.AcceptResponseHandler = func(_ *SmokescreenContext, resp *http.Response) error {
			resp.Header.Set(testHeader, "This header is added by the AcceptResponseHandler")
			return nil
		}
		r.NoError(err)

		err = cfg.SetAllowAddresses([]string{"127.0.0.1"})
		r.NoError(err)

		proxySrv := proxyServer(cfg)
		r.NoError(err)
		defer proxySrv.Close()

		// Create a http.Client that uses our proxy
		client, err := proxyClient(proxySrv.URL)
		r.NoError(err)

		// Send a request that should be allowed
		resp, err := client.Get(testSrv.URL)
		r.NoError(err)

		// The AcceptResponseHandler should set our custom header
		h := resp.Header.Get(testHeader)
		if h == "" {
			t.Errorf("Expecting header %s to be set by AcceptResponseHandler", testHeader)
		}
		// Send a request that should be blocked
		resp, err = client.Get("http://stripe.com")
		r.NoError(err)

		// The header set by our custom reject response handler should not be set
		h = resp.Header.Get(testHeader)
		if h != "" {
			t.Errorf("Expecting header %s to not be set by AcceptResponseHandler", testHeader)
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

	t.Run("PostDecisionRequestHandler works for HTTPS", func(t *testing.T) {
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
		cfg.PostDecisionRequestHandler = customRequestHandler

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

	t.Run("PostDecisionRequestHandler works for HTTP", func(t *testing.T) {
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
		cfg.PostDecisionRequestHandler = customRequestHandler

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
