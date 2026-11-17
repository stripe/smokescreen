package smokescreen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
)

func canonicalFixture(cfg *Config) *goproxy.ProxyCtx {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(traceHeader, "client-trace")
	sctx := newContext(cfg, httpProxy, req)
	sctx.Decision = &ACLDecision{allow: true, Reason: "allowed", Role: "service", Project: "project"}
	sctx.lookupTime = 1500 * time.Microsecond
	return &goproxy.ProxyCtx{Req: req, UserData: sctx}
}

func TestCanonicalDecisionSemantics(t *testing.T) {
	for _, tc := range []struct {
		name          string
		allow, report bool
		err           error
		level         string
	}{
		{"allow", true, false, nil, "INFO"},
		{"report", true, true, nil, "INFO"},
		{"deny", false, true, denyError{errors.New("denied")}, "WARN"},
		{"dial failure", true, false, errors.New("dial failed"), "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			cfg := NewConfig()
			cfg.Log = slog.New(slog.NewJSONHandler(&out, nil))
			pctx := canonicalFixture(cfg)
			sctx := pctx.UserData.(*SmokescreenContext)
			sctx.Decision.allow = tc.allow
			sctx.Decision.enforceWouldDeny = tc.report
			pctx.Error = tc.err
			logProxy(pctx)
			var record map[string]interface{}
			require.NoError(t, json.Unmarshal(out.Bytes(), &record))
			require.Equal(t, CanonicalProxyDecision, record["msg"])
			require.Equal(t, tc.level, record["level"])
			require.Equal(t, tc.allow, record[LogFieldAllow])
			require.Equal(t, tc.report, record[LogFieldEnforceWouldDeny])
			require.Equal(t, float64(1), record[LogFieldDNSLookupTime])
			require.Equal(t, "client-trace", record[LogFieldTraceID])
			require.NotEmpty(t, record[LogFieldID])
			require.Equal(t, sctx.start.UTC().Format(time.RFC3339Nano), record[LogFieldStartTime])
			require.NotContains(t, record, LogFieldContentLength)
			if tc.err == nil {
				require.NotContains(t, record, LogFieldError)
			} else {
				require.Equal(t, tc.err.Error(), record[LogFieldError])
			}
		})
	}
}

type deadlineResolver struct {
	t       *testing.T
	timeout time.Duration
	portCtx context.Context
	wait    bool
}

func (r *deadlineResolver) LookupPort(ctx context.Context, _, _ string) (int, error) {
	r.portCtx = ctx
	deadline, ok := ctx.Deadline()
	require.True(r.t, ok)
	require.InDelta(r.t, r.timeout.Seconds(), time.Until(deadline).Seconds(), 0.1)
	return 80, nil
}
func (r *deadlineResolver) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	require.Same(r.t, r.portCtx, ctx, "both lookups share one timeout")
	if r.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []net.IP{net.ParseIP("192.0.2.10")}, nil
}

func TestDNSOwnsTimeout(t *testing.T) {
	cfg := NewConfig()
	cfg.DNSTimeout = 10 * time.Millisecond
	cfg.Resolver = &deadlineResolver{t: t, timeout: cfg.DNSTimeout, wait: true}
	_, err := resolveTCPAddr(context.Background(), cfg, "tcp", "example.com:80")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// Inspect metadata during the callback, without retaining the live request context.
type observingResolver struct {
	Resolver
	observe func(context.Context, string, string)
}

func (r observingResolver) LookupPort(ctx context.Context, network, service string) (int, error) {
	r.observe(ctx, "port", service)
	return r.Resolver.LookupPort(ctx, network, service)
}

func (r observingResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	r.observe(ctx, "ip", host)
	return r.Resolver.LookupIP(ctx, network, host)
}

func assertRequestMetadata(t *testing.T, sctx *SmokescreenContext, role, trace string) {
	t.Helper()
	if !assert.NotNil(t, sctx.Decision) {
		return
	}
	assert.Equal(t, role, sctx.Decision.Role)
	assert.Equal(t, "security", sctx.Decision.Project)
	attrs := map[string]any{}
	counts := map[string]int{}
	for _, attr := range sctx.LogAttrs() {
		attrs[attr.Key] = attr.Value.Any()
		counts[attr.Key]++
	}
	assert.Equal(t, role, attrs[LogFieldRole])
	assert.Equal(t, "security", attrs[LogFieldProject])
	assert.Equal(t, trace, attrs[LogFieldTraceID])
	assert.NotEmpty(t, attrs[LogFieldID])
	assert.Equal(t, 1, counts[LogFieldRole])
	assert.Equal(t, 1, counts[LogFieldProject])
	assert.NotContains(t, attrs, LogFieldConnEstablishMS)
	assert.NotContains(t, attrs, LogFieldOutRemoteAddr)
}

func TestSmokescreenContextFromContext(t *testing.T) {
	for _, ctx := range []context.Context{
		context.Background(),
		context.WithValue(context.Background(), smokescreenContextKey{}, (*SmokescreenContext)(nil)),
		context.WithValue(context.Background(), smokescreenContextKey{}, "wrong type"),
	} {
		sctx, ok := SmokescreenContextFromContext(ctx)
		require.Nil(t, sctx)
		require.False(t, ok)
	}
}

func TestSafeResolveContext(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		noSctx  bool
	}{
		{name: "custom timeout", timeout: 10 * time.Millisecond},
		{name: "default timeout"},
		{name: "no request context", timeout: 10 * time.Millisecond, noSctx: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.DNSTimeout = tc.timeout
			reqCtx, cancel := context.WithCancel(context.Background())
			cancel()
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(reqCtx)
			sctx := newContext(cfg, httpProxy, req)
			if tc.noSctx {
				sctx = nil
			}
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			resolver := &deadlineResolver{t: t, timeout: timeout, wait: tc.timeout != 0}
			var lookupCtx context.Context
			var calls int
			cfg.Resolver = observingResolver{resolver, func(ctx context.Context, _, _ string) {
				calls++
				got, ok := SmokescreenContextFromContext(ctx)
				require.Equal(t, !tc.noSctx, ok)
				if tc.noSctx {
					require.Nil(t, got)
				} else {
					require.Same(t, sctx, got)
				}
				require.NoError(t, ctx.Err(), "DNS does not inherit request cancellation")
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.InDelta(t, timeout.Seconds(), time.Until(deadline).Seconds(), 0.1)
				if lookupCtx != nil {
					require.Same(t, lookupCtx, ctx)
				}
				lookupCtx = ctx
			}}
			_, _, err := safeResolve(cfg, sctx, "tcp", "example.com:80")
			if tc.timeout == 0 {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			require.Equal(t, 2, calls)
			require.Error(t, lookupCtx.Err(), "timeout context is canceled after resolution")
		})
	}
}

func TestFatalConfigExit(t *testing.T) {
	if os.Getenv("SMOKESCREEN_TEST_FATAL_CONFIG") == "1" {
		cfg := NewConfig()
		cfg.RejectResponseHandler = func(*http.Response) {}
		cfg.RejectResponseHandlerWithCtx = func(*SmokescreenContext, *http.Response) {}
		StartWithConfig(cfg, nil)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalConfigExit$")
	cmd.Env = append(os.Environ(), "SMOKESCREEN_TEST_FATAL_CONFIG=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 1, exit.ExitCode())
	require.Contains(t, string(out), "invalid config")
}

func TestLogAttrsIncludesBoundAndDialAttrs(t *testing.T) {
	var out bytes.Buffer
	cfg := NewConfig()
	cfg.Log = slog.New(slog.NewJSONHandler(&out, nil))
	pctx := canonicalFixture(cfg)
	sctx := pctx.UserData.(*SmokescreenContext)
	sctx.withLogAttrs(extractContextLogFields(sctx))
	sctx.dialAttrs = []slog.Attr{slog.Int64(LogFieldConnEstablishMS, 7)}

	got := map[string]slog.Value{}
	for _, attr := range sctx.LogAttrs() {
		got[attr.Key] = attr.Value
	}
	require.Equal(t, "client-trace", got[LogFieldTraceID].String())
	require.Equal(t, "service", got[LogFieldRole].String())
	require.Equal(t, "project", got[LogFieldProject].String())
	require.Equal(t, int64(7), got[LogFieldConnEstablishMS].Int64())
	require.NotEmpty(t, got[LogFieldID].String())

	// The accessor mirrors what Logger itself attaches.
	sctx.Logger.Info("probe")
	var record map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Bytes(), &record))
	require.Equal(t, "service", record[LogFieldRole])
	require.Equal(t, "client-trace", record[LogFieldTraceID])

	// Callers get a copy.
	attrs := sctx.LogAttrs()
	attrs[0] = slog.String("mutated", "x")
	require.NotEqual(t, "mutated", sctx.LogAttrs()[0].Key)
}
