//go:build !nounit

package smokescreen

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/v2/internal/testlog"
	acl "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
	"github.com/stripe/smokescreen/v2/pkg/smokescreen/conntrack"
)

func httpLoggingProxy(t *testing.T) (*goproxy.ProxyHttpServer, *testlog.Handler) {
	t.Helper()
	cfg := NewConfig()
	records := proxyLogHook(cfg)
	require.NoError(t, cfg.SetAllowAddresses([]string{"127.0.0.1"}))
	cfg.ConnTracker = conntrack.NewTracker(cfg.IdleTimeout, cfg.MetricsClient, cfg.ShuttingDown, nil)
	cfg.RoleFromRequest = func(req *http.Request) (string, error) {
		return req.Header.Get(roleHeader), nil
	}
	var err error
	cfg.EgressACL, err = acl.Compile(&acl.Policy{
		Version: acl.Version,
		Services: []acl.Service{
			{
				Name: "first", Project: "project-first", Action: acl.ModeOpen,
			},
			{
				Name: "second", Project: "project-second", Action: acl.ModeOpen,
			},
		},
	}, acl.Options{})
	require.NoError(t, err)
	proxy := BuildProxy(cfg)
	proxy.Tr.Proxy = nil
	t.Cleanup(proxy.Tr.CloseIdleConnections)
	return proxy, records
}

func httpCompletionRecords(records *testlog.Handler) []*testlog.Entry {
	var completions []*testlog.Entry
	for _, entry := range records.AllEntries() {
		if entry.Message == CanonicalProxyRequestClose {
			completions = append(completions, entry)
		}
	}
	return completions
}

func TestHTTPCompletionLogsConsumersOnPooledConnection(t *testing.T) {
	addresses := make(chan string, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		addresses <- req.RemoteAddr
		_, err := io.Copy(w, req.Body)
		assert.NoError(t, err)
	}))
	t.Cleanup(backend.Close)
	proxy, records := httpLoggingProxy(t)
	cases := []struct {
		role    string
		payload string
	}{
		{
			role: "first", payload: "one",
		},
		{
			role: "second", payload: "second request",
		},
	}
	for index, testCase := range cases {
		req := httptest.NewRequest(http.MethodPost, backend.URL, strings.NewReader(testCase.payload))
		req.Header.Set(roleHeader, testCase.role)
		req.Header.Set(traceHeader, testCase.role+"-trace")
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code)
		require.Equal(t, testCase.payload, recorder.Body.String())
		require.Eventually(t, func() bool {
			return len(httpCompletionRecords(records)) == index+1
		}, time.Second, time.Millisecond)
		entry := httpCompletionRecords(records)[index]
		assert.Equal(t, slog.LevelInfo, entry.Level)
		assert.Equal(t, uint64(len(testCase.payload)), entry.Data[conntrack.LogFieldBytesIn])
		assert.Equal(t, uint64(len(testCase.payload)), entry.Data[conntrack.LogFieldBytesOut])
		assert.Equal(t, testCase.role, entry.Data[LogFieldRole])
		assert.Equal(t, "project-"+testCase.role, entry.Data[LogFieldProject])
		assert.Equal(t, testCase.role+"-trace", entry.Data[LogFieldTraceID])
		assert.Equal(t, req.Host, entry.Data[LogFieldRequestedHost])
		assert.Equal(t, httpProxy, entry.Data[LogFieldProxyType])
		assert.Equal(t, int64(http.StatusOK), entry.Data["status_code"])
		assert.Equal(t, "", entry.Data[LogFieldError])
		assert.Equal(t, true, entry.Data[LogFieldAllow])
		assert.NotEmpty(t, entry.Data[LogFieldID])
		assert.GreaterOrEqual(t, entry.Data[conntrack.LogFieldDuration], float64(0))
		assert.IsType(t, time.Time{}, entry.Data[conntrack.LogFieldEndTime])
		assert.Equal(t, backend.Listener.Addr().String(), entry.Data[LogFieldOutRemoteAddr])
		assert.NotEmpty(t, entry.Data[LogFieldOutLocalAddr])
	}
	require.Equal(t, <-addresses, <-addresses, "test must reuse the outbound connection")
	completions := httpCompletionRecords(records)
	assert.NotEqual(t, completions[0].Data[LogFieldID], completions[1].Data[LogFieldID])
	assert.Equal(t, completions[0].Data[LogFieldOutLocalAddr], completions[1].Data[LogFieldOutLocalAddr])
	assert.Nil(t, findCanonicalProxyClose(records.AllEntries()))
}

func TestHTTPDecisionPrecedesStreamCompletion(t *testing.T) {
	headersSent := make(chan struct{})
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(headersSent)
		select {
		case <-release:
			_, err := io.WriteString(w, "streamed")
			assert.NoError(t, err)
		case <-req.Context().Done():
		}
	}))
	t.Cleanup(backend.Close)
	proxy, records := httpLoggingProxy(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodGet, backend.URL, nil)
		req.Header.Set(roleHeader, "first")
		proxy.ServeHTTP(httptest.NewRecorder(), req)
	}()
	t.Cleanup(func() { close(release); <-done })
	<-headersSent
	require.Eventually(t, func() bool {
		return findCanonicalProxyDecision(records.AllEntries()) != nil
	}, time.Second, time.Millisecond)
	assert.Empty(t, httpCompletionRecords(records), "headers do not complete a streamed request")
	release <- struct{}{}
	<-done
	completions := httpCompletionRecords(records)
	require.Len(t, completions, 1)
	assert.Equal(t, uint64(8), completions[0].Data[conntrack.LogFieldBytesIn])
	assert.Equal(t, uint64(0), completions[0].Data[conntrack.LogFieldBytesOut])
}

func TestHTTPCompletionLogsPartialFailureAndRejection(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		statusCode int
		level      slog.Level
		bytesIn    uint64
		wantError  bool
	}{
		{
			name: "partial response", role: "first", statusCode: http.StatusOK,
			level: slog.LevelError, bytesIn: 3, wantError: true,
		},
		{
			name: "ACL rejection", role: "unknown", statusCode: http.StatusProxyAuthRequired,
			level: slog.LevelWarn,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Length", "10")
				_, err := io.WriteString(w, "abc")
				assert.NoError(t, err)
			}))
			t.Cleanup(backend.Close)
			proxy, records := httpLoggingProxy(t)
			req := httptest.NewRequest(http.MethodGet, backend.URL, nil)
			req.Header.Set(roleHeader, testCase.role)
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, req)
			assert.Equal(t, testCase.statusCode, recorder.Code)
			completions := httpCompletionRecords(records)
			require.Len(t, completions, 1)
			entry := completions[0]
			assert.Equal(t, testCase.level, entry.Level)
			assert.Equal(t, testCase.bytesIn, entry.Data[conntrack.LogFieldBytesIn])
			assert.Equal(t, uint64(0), entry.Data[conntrack.LogFieldBytesOut])
			if testCase.wantError {
				assert.Contains(t, entry.Data[LogFieldError], io.ErrUnexpectedEOF.Error())
			} else {
				assert.Empty(t, entry.Data[LogFieldError])
				assert.Equal(t, false, entry.Data[LogFieldAllow])
				assert.NotEmpty(t, entry.Data[LogFieldDecisionReason])
			}
			assert.Equal(t, int64(testCase.statusCode), entry.Data["status_code"])
		})
	}
}
