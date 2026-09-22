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

	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
)

func canonicalFixture(cfg *Config) *goproxy.ProxyCtx {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(traceHeader, "client-trace")
	sctx := newContext(cfg, httpProxy, req, nil)
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
}

func (r deadlineResolver) LookupPort(ctx context.Context, _, _ string) (int, error) {
	deadline, ok := ctx.Deadline()
	require.True(r.t, ok)
	require.InDelta(r.t, r.timeout.Seconds(), time.Until(deadline).Seconds(), 0.1)
	return 80, nil
}
func (r deadlineResolver) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDNSOwnsTimeout(t *testing.T) {
	cfg := NewConfig()
	cfg.DNSTimeout = 10 * time.Millisecond
	cfg.Resolver = deadlineResolver{t, cfg.DNSTimeout}
	_, err := resolveTCPAddr(context.Background(), cfg, cfg.Log, "tcp", "example.com:80")
	require.ErrorIs(t, err, context.DeadlineExceeded)
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
	require.Contains(t, string(out), `"level":"ERROR"`)
}
