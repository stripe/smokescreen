//go:build !nounit
// +build !nounit

package smokescreen

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/v2/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/v2/pkg/smokescreen/metrics"
)

// Embed the real tracker to retain connection wrapping, and record attempt calls.
type dialErrorTracker struct {
	conntrack.TrackerInterface
	attempts int
	host     string
	success  bool
	at       time.Time
}

func (tr *dialErrorTracker) RecordAttempt(host string, success bool) {
	tr.attempts++
	tr.host, tr.success, tr.at = host, success, time.Now()
	tr.TrackerInterface.RecordAttempt(host, success)
}

func dialErrorContext(t *testing.T, proxyType string) (context.Context, *SmokescreenContext, *dialErrorTracker) {
	t.Helper()
	cfg, err := testConfig("test-local-srv")
	require.NoError(t, err)
	tr := &dialErrorTracker{TrackerInterface: cfg.ConnTracker}
	cfg.ConnTracker = tr
	cfg.TunnelLimiter = NewTunnelLimiter(1, cfg)
	req := httptest.NewRequest(http.MethodGet, "http://destination.test:443", nil)
	sctx := newContext(cfg, proxyType, req)
	sctx.Decision = &ACLDecision{
		OutboundHost: "destination.test:443",
		ResolvedAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443},
	}
	pctx := &goproxy.ProxyCtx{Req: req, UserData: sctx}
	return context.WithValue(req.Context(), goproxy.ProxyContextKey, pctx), sctx, tr
}

func TestOnDialErrorFailure(t *testing.T) {
	for _, proxyType := range []string{httpProxy, connectProxy} {
		for _, hook := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hook=%t", proxyType, hook), func(t *testing.T) {
				ctx, sctx, tr := dialErrorContext(t, proxyType)
				cfg := sctx.cfg
				cause := errors.New("injected failure")
				dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("wrapped: %w", cause)}
				var calls, notifications int
				var dialFinished time.Time
				cfg.ProxyDialTimeout = func(gotCtx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
					calls++
					assert.Same(t, ctx, gotCtx)
					assert.Equal(t, "tcp", network)
					assert.Equal(t, "192.0.2.10:443", address)
					assert.Equal(t, cfg.ConnectTimeout, timeout)
					if proxyType == connectProxy {
						assert.Equal(t, int64(1), cfg.TunnelLimiter.ActiveCount())
					}
					// Mutate both address storage and decision metadata during the dial.
					sctx.Decision.ResolvedAddr.IP[0] ^= 0xff
					sctx.Decision.ResolvedAddr.Port = 8443
					sctx.Decision.OutboundHost = "changed.test:8443"
					dialFinished = time.Now()
					return nil, dialErr
				}
				if hook {
					cfg.OnDialError = func(gotCtx context.Context, event DialErrorEvent) {
						notifications++
						assert.Same(t, ctx, gotCtx)
						assert.Equal(t, "tcp", event.Network)
						assert.Equal(t, "destination.test:443", event.TargetAddr)
						assert.Equal(t, "192.0.2.10:443", event.ResolvedAddr)
						assert.Equal(t, "destination.test:443", event.RequestDestination)
						assert.Same(t, dialErr, event.Err)
						assert.ErrorIs(t, event.Err, cause)
						var typed *net.OpError
						assert.ErrorAs(t, event.Err, &typed)
						assert.False(t, event.CompletedAt.Before(dialFinished))
						assert.False(t, event.CompletedAt.After(tr.at), "completion precedes failure accounting")
						assert.Equal(t, 1, tr.attempts)
						assert.False(t, tr.success)
						assert.Equal(t, int64(0), cfg.TunnelLimiter.ActiveCount())
						assert.False(t, sctx.tunnelSlotAcquired)
						count, err := cfg.MetricsClient.(*metrics.MockMetricsClient).GetCount("cn.atpt.connect.err", map[string]string{"type": "unknown"})
						assert.NoError(t, err)
						assert.Equal(t, uint64(1), count)
					}
				}
				conn, err := dialContext(ctx, "tcp", "destination.test:443")
				require.Nil(t, conn)
				require.Same(t, dialErr, err)
				require.Equal(t, 1, calls)
				if hook {
					require.Equal(t, 1, notifications)
				} else {
					require.Zero(t, notifications)
				}
				require.Equal(t, 1, tr.attempts)
				require.Equal(t, "destination.test:443", tr.host)
				require.False(t, tr.success)
				require.Zero(t, cfg.TunnelLimiter.ActiveCount())
				count, err := cfg.MetricsClient.(*metrics.MockMetricsClient).GetCount("cn.atpt.total", map[string]string{"success": "false"})
				require.NoError(t, err)
				require.Equal(t, uint64(1), count)
			})
		}
	}
}

func TestOnDialErrorDefaultDialer(t *testing.T) {
	ctx, sctx, tr := dialErrorContext(t, connectProxy)
	// A negative timeout fails immediately, without waiting for a network timeout.
	sctx.cfg.ConnectTimeout = -1
	var events []DialErrorEvent
	sctx.cfg.OnDialError = func(_ context.Context, event DialErrorEvent) { events = append(events, event) }
	before := time.Now()
	conn, err := dialContext(ctx, "tcp", "destination.test:443")
	after := time.Now()
	require.Nil(t, conn)
	require.Error(t, err)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())
	require.Len(t, events, 1)
	require.Same(t, err, events[0].Err)
	require.False(t, events[0].CompletedAt.Before(before))
	require.False(t, events[0].CompletedAt.After(after))
	require.Equal(t, 1, tr.attempts)
	require.Zero(t, sctx.cfg.TunnelLimiter.ActiveCount())
	count, err := sctx.cfg.MetricsClient.(*metrics.MockMetricsClient).GetCount("cn.atpt.connect.err", map[string]string{"type": "timeout"})
	require.NoError(t, err)
	require.Equal(t, uint64(1), count)
}

func TestOnDialErrorSuccess(t *testing.T) {
	for _, proxyType := range []string{httpProxy, connectProxy} {
		t.Run(proxyType, func(t *testing.T) {
			ctx, sctx, tr := dialErrorContext(t, proxyType)
			local, remote := net.Pipe()
			defer remote.Close()
			var calls, notifications int
			sctx.cfg.ProxyDialTimeout = func(context.Context, string, string, time.Duration) (net.Conn, error) {
				calls++
				return local, nil
			}
			sctx.cfg.OnDialError = func(context.Context, DialErrorEvent) { notifications++ }
			conn, err := dialContext(ctx, "tcp", "destination.test:443")
			require.NoError(t, err)
			require.NotNil(t, conn)
			require.Equal(t, 1, calls)
			require.Equal(t, 1, tr.attempts)
			require.True(t, tr.success)
			// Established-connection errors and closure must not notify the dial hook.
			require.NoError(t, remote.Close())
			_, err = conn.Read(make([]byte, 1))
			require.Error(t, err)
			require.NoError(t, conn.Close())
			require.Zero(t, notifications)
			require.Zero(t, sctx.cfg.TunnelLimiter.ActiveCount())
		})
	}
}

// Return fixed DNS results to keep proxy-path tests independent of external DNS.
type dialErrorResolver struct {
	err error
}

func (r dialErrorResolver) LookupPort(_ context.Context, _, service string) (int, error) {
	return strconv.Atoi(service)
}

func (r dialErrorResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("192.0.2.10")}, r.err
}

func TestOnDialErrorBeforeDial(t *testing.T) {
	for _, failure := range []string{"dns", "address rejection", "tunnel limit", "missing context", "invalid network"} {
		t.Run(failure, func(t *testing.T) {
			ctx, sctx, tr := dialErrorContext(t, connectProxy)
			var calls, notifications int
			sctx.cfg.ProxyDialTimeout = func(context.Context, string, string, time.Duration) (net.Conn, error) {
				calls++
				return nil, errors.New("unexpected dial")
			}
			sctx.cfg.OnDialError = func(context.Context, DialErrorEvent) { notifications++ }
			network := "tcp"
			switch failure {
			case "dns":
				sctx.Decision.ResolvedAddr = nil
				sctx.cfg.Resolver = dialErrorResolver{err: &net.DNSError{Err: "injected DNS failure", Name: "destination.test"}}
			case "address rejection":
				sctx.Decision.ResolvedAddr = nil
				sctx.cfg.Resolver = dialErrorResolver{}
				require.NoError(t, sctx.cfg.SetDenyAddresses([]string{"192.0.2.10"}))
			case "tunnel limit":
				require.True(t, sctx.cfg.TunnelLimiter.Acquire())
				defer sctx.cfg.TunnelLimiter.Release()
			case "missing context":
				ctx = context.Background()
			case "invalid network":
				network = "udp"
			}
			conn, err := dialContext(ctx, network, "destination.test:443")
			require.Nil(t, conn)
			require.Error(t, err)
			require.Zero(t, calls)
			require.Zero(t, notifications)
			require.Zero(t, tr.attempts)
			require.False(t, sctx.tunnelSlotAcquired)
			if failure == "tunnel limit" {
				var limitErr tunnelLimitError
				require.ErrorAs(t, err, &limitErr)
				require.EqualError(t, limitErr, ErrTunnelLimitExceeded.Error())
				require.Equal(t, int64(1), sctx.cfg.TunnelLimiter.ActiveCount())
			}
		})
	}
}

func TestOnDialErrorProxyPaths(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		for _, upstream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/upstream=%t", method, upstream), func(t *testing.T) {
				cfg, err := testConfig("test-local-srv")
				require.NoError(t, err)
				cfg.Resolver = dialErrorResolver{}
				cfg.TunnelLimiter = NewTunnelLimiter(1, cfg)
				if upstream {
					cfg.UpstreamHttpProxyAddr = "http://proxy.test:8080"
					cfg.UpstreamHttpsProxyAddr = "http://proxy.test:8080"
				}
				dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("injected failure")}
				var calls atomic.Int32
				events := make(chan DialErrorEvent, 2)
				cfg.ProxyDialTimeout = func(context.Context, string, string, time.Duration) (net.Conn, error) {
					calls.Add(1)
					return nil, dialErr
				}
				cfg.OnDialError = func(_ context.Context, event DialErrorEvent) { events <- event }
				proxy := proxyServer(cfg)
				defer proxy.Close()
				conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
				require.NoError(t, err)
				defer conn.Close()
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				target := "http://destination.test:443/"
				if method == http.MethodConnect {
					target = "destination.test:443"
				}
				_, err = fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: destination.test:443\r\nConnection: close\r\n\r\n", method, target)
				require.NoError(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, http.StatusBadGateway, resp.StatusCode)
				require.Equal(t, int32(1), calls.Load())
				require.Len(t, events, 1)
				event := <-events
				require.Same(t, dialErr, event.Err)
				require.Equal(t, "tcp", event.Network)
				require.Equal(t, "destination.test:443", event.RequestDestination)
				if upstream {
					require.Equal(t, "proxy.test:8080", event.TargetAddr)
					require.Equal(t, "192.0.2.10:8080", event.ResolvedAddr)
				} else {
					require.Equal(t, "destination.test:443", event.TargetAddr)
					require.Equal(t, "192.0.2.10:443", event.ResolvedAddr)
				}
				require.Zero(t, cfg.TunnelLimiter.ActiveCount())
			})
		}
	}
}

func TestOnDialErrorRequestRejection(t *testing.T) {
	for _, failure := range []string{"acl", "admission"} {
		t.Run(failure, func(t *testing.T) {
			cfg, err := testConfig("test-trusted-srv")
			require.NoError(t, err)
			var calls, notifications int
			cfg.ProxyDialTimeout = func(context.Context, string, string, time.Duration) (net.Conn, error) {
				calls++
				return nil, errors.New("unexpected dial")
			}
			cfg.OnDialError = func(context.Context, DialErrorEvent) { notifications++ }
			var handler http.Handler = BuildProxy(cfg)
			expected := http.StatusProxyAuthRequired
			if failure == "admission" {
				cfg.MaxConcurrentRequests = 1
				limited := NewRateLimitedHandler(handler, cfg)
				limited.concurrencyLimiter <- struct{}{}
				handler = limited
				expected = http.StatusServiceUnavailable
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://blocked.test/", nil))
			require.Equal(t, expected, recorder.Code)
			require.Zero(t, calls)
			require.Zero(t, notifications)
		})
	}
}

func TestOnDialErrorConcurrent(t *testing.T) {
	cfg, err := testConfig("test-local-srv")
	require.NoError(t, err)
	dialErr := errors.New("injected failure")
	cfg.ProxyDialTimeout = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return nil, dialErr
	}
	var notifications atomic.Int32
	cfg.OnDialError = func(_ context.Context, event DialErrorEvent) {
		notifications.Add(1)
		assert.Same(t, dialErr, event.Err)
		assert.Equal(t, "192.0.2.10:80", event.TargetAddr)
		assert.Equal(t, "192.0.2.10:80", event.ResolvedAddr)
	}
	t.Run("concurrent dials", func(t *testing.T) {
		for i := 0; i < 16; i++ {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()
				req := httptest.NewRequest(http.MethodGet, "http://192.0.2.10/", nil)
				sctx := newContext(cfg, httpProxy, req)
				sctx.Decision = &ACLDecision{
					OutboundHost: "192.0.2.10:80",
					ResolvedAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 80},
				}
				ctx := context.WithValue(req.Context(), goproxy.ProxyContextKey, &goproxy.ProxyCtx{Req: req, UserData: sctx})
				conn, err := dialContext(ctx, "tcp", "192.0.2.10:80")
				require.Nil(t, conn)
				require.Same(t, dialErr, err)
			})
		}
	})
	require.Equal(t, int32(16), notifications.Load())
}
