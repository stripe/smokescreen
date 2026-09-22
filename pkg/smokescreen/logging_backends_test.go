package smokescreen

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/internal/testlog"
)

// Capture the same attributes passed to each real backend, including groups.
type captureHandler struct {
	slog.Handler
	records *testlog.Handler
}

func (h captureHandler) Handle(ctx context.Context, r slog.Record) error {
	h.records.Handle(ctx, r)
	return h.Handler.Handle(ctx, r)
}
func (h captureHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return captureHandler{h.Handler.WithAttrs(a), h.records.WithAttrs(a).(*testlog.Handler)}
}
func (h captureHandler) WithGroup(g string) slog.Handler {
	return captureHandler{h.Handler.WithGroup(g), h.records.WithGroup(g).(*testlog.Handler)}
}

type failingHandler struct{ slog.Handler }

func (h failingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.Handler.Handle(ctx, r)
	return errors.New("export failed")
}
func (h failingHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return failingHandler{h.Handler.WithAttrs(a)}
}
func (h failingHandler) WithGroup(g string) slog.Handler {
	return failingHandler{h.Handler.WithGroup(g)}
}

func TestProxyLoggingBackends(t *testing.T) {
	for _, backend := range []string{"json", "text", "caller", "error", "disabled"} {
		for _, mode := range []string{"http", "connect", "mitm", "deny"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				cfg, err := testConfig("test-local-srv")
				require.NoError(t, err)
				require.NoError(t, cfg.SetAllowAddresses([]string{"127.0.0.1"}))
				if mode == "mitm" {
					cfg.RoleFromRequest = func(*http.Request) (string, error) { return "test-mitm", nil }
					ca, err := tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
					require.NoError(t, err)
					ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
					require.NoError(t, err)
					cfg.MitmTLSConfig = goproxy.TLSConfigFromCA(&ca)
				}
				if mode == "deny" {
					cfg.RoleFromRequest = func(*http.Request) (string, error) { return "unknown", nil }
				}
				records := &testlog.Handler{}
				var handler slog.Handler = records
				if backend == "json" {
					handler = captureHandler{slog.NewJSONHandler(io.Discard, nil), records}
				}
				if backend == "text" {
					handler = captureHandler{slog.NewTextHandler(io.Discard, nil), records}
				}
				if backend == "error" {
					handler = failingHandler{records}
				}
				if backend == "disabled" {
					handler = slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1})
				}
				cfg.Log = slog.New(handler).With(slog.String("integration", backend)).WithGroup("proxy")
				proxy := BuildProxy(cfg)
				server := httptest.NewServer(proxy)
				defer server.Close()
				originHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
				var origin *httptest.Server
				if mode == "connect" || mode == "mitm" {
					origin = httptest.NewTLSServer(originHandler)
				} else {
					origin = httptest.NewServer(originHandler)
				}
				defer origin.Close()
				client, err := proxyClientWithConnectHeaders(server.URL, http.Header{traceHeader: {"client-trace"}})
				require.NoError(t, err)
				defer client.CloseIdleConnections()
				resp, err := client.Get(origin.URL)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.NoError(t, err)
				if mode == "deny" {
					require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
				} else {
					require.Equal(t, 200, resp.StatusCode)
					require.Equal(t, "ok", string(body))
				}
				client.CloseIdleConnections()
				proxy.Tr.CloseIdleConnections()
				if backend == "disabled" {
					require.Empty(t, records.AllEntries())
					return
				}
				if mode == "connect" || mode == "mitm" {
					require.Eventually(t, func() bool { return findCanonicalProxyClose(records.AllEntries()) != nil }, time.Second, time.Millisecond)
				}
				entry := findCanonicalProxyDecision(records.AllEntries())
				require.NotNil(t, entry)
				require.Equal(t, backend, entry.Data["integration"])
				fields := entry.Data["proxy"].(map[string]any)
				require.NotEmpty(t, fields[LogFieldID])
				require.Equal(t, mode != "deny", fields[LogFieldAllow])
				wantLevel := slog.LevelInfo
				if mode == "deny" {
					wantLevel = slog.LevelWarn
				}
				require.Equal(t, wantLevel, entry.Level)
				if mode == "mitm" {
					closeFields := findCanonicalProxyClose(records.AllEntries()).Data["proxy"].(map[string]any)
					require.Equal(t, fields[LogFieldID], closeFields[LogFieldParentID])
					require.NotEqual(t, fields[LogFieldID], closeFields[LogFieldID])
					require.Equal(t, "client-trace", closeFields[LogFieldTraceID])
					headers := closeFields[LogMitmReqHeaders].(http.Header)
					require.Equal(t, "[REDACTED]", headers.Get("Accept-Language"))
				}
			})
		}
	}
}

func TestRedactionBeforeHandler(t *testing.T) {
	logger, records := testlog.New()
	cfg := NewConfig()
	cfg.Log = logger
	pctx := canonicalFixture(cfg)
	pctx.Error = errors.New("dial https://alice:secret@proxy.example/?token=secret failed")
	logProxy(pctx)
	require.NotContains(t, records.LastEntry().Data[LogFieldError], "secret")
	input := http.Header{"User-Agent": {"before"}, "Authorization": {"secret"}}
	output := redactHeaders(input, []string{"User-Agent"})
	input["User-Agent"][0] = "after"
	require.Equal(t, "before", output.Get("User-Agent"))
	require.Equal(t, "[REDACTED]", output.Get("Authorization"))
}

func TestChangingStatusDoesNotAccumulateKeys(t *testing.T) {
	var output bytes.Buffer
	cfg := NewConfig()
	cfg.Log = slog.New(slog.NewJSONHandler(&output, nil))
	pctx := canonicalFixture(cfg)
	rejectResponse(pctx, errors.New("first failure"))
	rejectResponse(pctx, denyError{errors.New("denied")})
	logProxy(pctx)
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.Contains(line, CanonicalProxyDecision) {
			require.Equal(t, 1, strings.Count(line, `"status_code":`))
			require.Contains(t, line, `"status_code":407`)
		}
	}
}

func TestConcurrentBackendIsolation(t *testing.T) {
	var wg sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			var out bytes.Buffer
			cfg := NewConfig()
			cfg.Log = slog.New(slog.NewJSONHandler(&out, nil)).With("instance", name)
			proxy := BuildProxy(cfg)
			proxy.Logger.Print("instance diagnostic")
			logProxy(canonicalFixture(cfg))
			require.Contains(t, out.String(), `"instance":"`+name+`"`)
			other := "second"
			if name == "second" {
				other = "first"
			}
			require.NotContains(t, out.String(), `"instance":"`+other+`"`)
		}(name)
	}
	wg.Wait()
}
