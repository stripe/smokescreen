package smokescreen

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/internal/testlog"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

type loggingContextKey struct{}

func TestCanceledContextDeliveredToLogging(t *testing.T) {
	logger, records := testlog.New()
	cfg := NewConfig()
	cfg.Log = logger
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), loggingContextKey{}, "trusted-trace"))
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil).WithContext(ctx)
	req.Header.Set(traceHeader, "untrusted-client-trace")
	sctx := newContext(cfg, httpProxy, req, nil)
	sctx.Decision = &ACLDecision{allow: true}
	cancel()
	logProxy(&goproxy.ProxyCtx{Req: req, UserData: sctx})
	record := records.LastEntry()
	require.Same(t, ctx, record.Context)
	require.ErrorIs(t, record.Context.Err(), context.Canceled)
	require.Equal(t, "trusted-trace", record.Context.Value(loggingContextKey{}))
	require.Equal(t, "untrusted-client-trace", record.Data[LogFieldTraceID])
	for _, enabledCtx := range records.EnabledContexts() {
		require.Same(t, ctx, enabledCtx)
	}
}

type uncanceledResolver struct{ t *testing.T }

func (r uncanceledResolver) LookupPort(ctx context.Context, _, _ string) (int, error) {
	require.NoError(r.t, ctx.Err())
	_, ok := ctx.Deadline()
	require.True(r.t, ok)
	return 80, nil
}
func (r uncanceledResolver) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	require.NoError(r.t, ctx.Err())
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

func TestCanceledLoggingContextDoesNotCancelDNS(t *testing.T) {
	logger, records := testlog.New()
	cfg := NewConfig()
	cfg.Log = logger
	cfg.Resolver = uncanceledResolver{t}
	cfg.TemporarilyDeferredIPs = []string{"127.0.0.1"}
	require.NoError(t, cfg.SetAllowAddresses([]string{"127.0.0.1"}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addr, err := resolveTCPAddr(ctx, cfg, logger.With("id", "request"), "tcp", "example.com:80")
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:80", addr.String())
	for _, entry := range records.AllEntries() {
		require.Same(t, ctx, entry.Context)
		require.Equal(t, "request", entry.Data[LogFieldID])
	}
	require.NotEmpty(t, records.AllEntries())
}

func TestCanceledContextPreservesDialingBehavior(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	cfg := NewConfig()
	cfg.ConnTracker = conntrack.NewTracker(0, cfg.MetricsClient, cfg.ShuttingDown, nil)
	req := httptest.NewRequest(http.MethodGet, "http://"+listener.Addr().String(), nil)
	sctx := newContext(cfg, httpProxy, req, nil)
	sctx.Decision = &ACLDecision{allow: true, OutboundHost: listener.Addr().String(), ResolvedAddr: listener.Addr().(*net.TCPAddr)}
	pctx := &goproxy.ProxyCtx{Req: req, UserData: sctx}
	ctx, cancel := context.WithCancel(context.WithValue(req.Context(), goproxy.ProxyContextKey, pctx))
	cancel()
	// The built-in net.DialTimeout continues to ignore request cancellation.
	conn, err := dialContext(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	conn.Close()
	// Custom dialers still receive the original operational context unchanged.
	cfg.ProxyDialTimeout = func(got context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		require.Same(t, ctx, got)
		return nil, got.Err()
	}
	_, err = dialContext(ctx, "tcp", listener.Addr().String())
	require.True(t, errors.Is(err, context.Canceled))
}

func TestMITMCorrelation(t *testing.T) {
	logger, records := testlog.New()
	cfg := NewConfig()
	cfg.Log = logger
	connect := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	connect.Header.Set(traceHeader, "client-trace")
	parent := newContext(cfg, connectProxy, connect, nil)
	connect.Header.Del(traceHeader)
	for i := 0; i < 2; i++ {
		inner := newContext(cfg, connectProxy, httptest.NewRequest(http.MethodGet, "https://example.com", nil), parent)
		inner.Logger.InfoContext(inner.loggingContext(), "inner")
		e := records.LastEntry()
		require.Equal(t, parent.id, e.Data[LogFieldParentID])
		require.NotEqual(t, parent.id, e.Data[LogFieldID])
		require.Equal(t, "client-trace", e.Data[LogFieldTraceID])
	}
	entries := records.AllEntries()
	require.NotEqual(t, entries[0].Data[LogFieldID], entries[1].Data[LogFieldID])
}
