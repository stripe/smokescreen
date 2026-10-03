package smokescreen

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

type bypassTestResolver struct{}

func (bypassTestResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}
func (bypassTestResolver) LookupPort(ctx context.Context, network, service string) (int, error) {
	return net.DefaultResolver.LookupPort(ctx, network, service)
}

func TestIPFilterBypassPolicy(t *testing.T) {
	config := NewConfig()
	require.NoError(t, config.SetUnsafeIPFilterBypassedDomains([]string{"*.internal.example.com"}))
	for _, host := range []string{"internal.example.com", "internal.example.com.evil", "127.0.0.1", "unrelated.example.com"} {
		require.False(t, bypassIPFiltersForHost(config, host), host)
	}
	require.True(t, bypassIPFiltersForHost(config, "LOGIN.INTERNAL.EXAMPLE.COM."))
	require.NoError(t, config.SetDenyRanges([]string{"0.0.0.0/0", "::/0"}))
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "fc00::1", "64:ff9b::a00:1", "8.8.8.8"} {
		addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 80}
		require.False(t, classifyAddrWithIPFilterBypass(config, addr, false).IsAllowed(), ip)
		require.True(t, classifyAddrWithIPFilterBypass(config, addr, true).IsAllowed(), ip)
	}
	config.LocalIPs = []net.IP{net.ParseIP("10.0.0.1")}
	addr := &net.TCPAddr{IP: config.LocalIPs[0], Port: 80}
	require.Equal(t, ipDenySelfConnection, classifyAddrWithIPFilterBypass(config, addr, true))
	config.AllowSelfConnections = true
	require.True(t, classifyAddrWithIPFilterBypass(config, addr, true).IsAllowed())
	config.UnsafeIPFilterBypassedDomains = []string{"*"}
	require.Error(t, config.Validate())
}

func TestIPFilterBypassHTTPAndCONNECT(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(targetURL.Host)
	require.NoError(t, err)
	for _, tunnel := range []bool{false, true} {
		t.Run(fmt.Sprintf("CONNECT=%t", tunnel), func(t *testing.T) {
			config := NewConfig()
			config.Resolver = bypassTestResolver{}
			config.RoleFromRequest = func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Role"), nil }
			config.EgressACL = &acl.ACL{Rules: map[string]acl.Rule{"allowed": {Policy: acl.Enforce, DomainGlobs: []string{"*.internal.example.com"}}, "denied": {Policy: acl.Enforce}}}
			config.ConnTracker = conntrack.NewTracker(config.IdleTimeout, config.MetricsClient, config.Log, atomic.Value{}, nil)
			require.NoError(t, config.SetDenyAddresses([]string{"127.0.0.1"}))
			require.NoError(t, config.SetUnsafeIPFilterBypassedDomains([]string{"login.internal.example.com"}))
			proxy := httptest.NewServer(BuildProxy(config))
			defer proxy.Close()
			for _, tc := range []struct {
				host, role string
				status     int
			}{
				{"login.internal.example.com", "allowed", http.StatusNoContent},
				{"login.internal.example.com", "denied", http.StatusProxyAuthRequired},
				{"other.internal.example.com", "allowed", http.StatusProxyAuthRequired},
			} {
				proxyURL, err := url.Parse(proxy.URL)
				require.NoError(t, err)
				conn, err := net.Dial("tcp", proxyURL.Host)
				require.NoError(t, err)
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				hostPort := net.JoinHostPort(tc.host, port)
				if tunnel {
					_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Test-Role: %s\r\n\r\n", hostPort, hostPort, tc.role)
				} else {
					_, err = fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nX-Test-Role: %s\r\nConnection: close\r\n\r\n", hostPort, hostPort, tc.role)
				}
				require.NoError(t, err)
				reader := bufio.NewReader(conn)
				resp, err := http.ReadResponse(reader, nil)
				require.NoError(t, err)
				if tunnel && tc.status == http.StatusNoContent {
					require.Equal(t, http.StatusOK, resp.StatusCode)
					_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostPort)
					require.NoError(t, err)
					resp, err = http.ReadResponse(reader, nil)
					require.NoError(t, err)
				}
				require.Equal(t, tc.status, resp.StatusCode, "%s/%s", tc.host, tc.role)
				resp.Body.Close()
				conn.Close()
			}
		})
	}
}

func TestIPFilterBypassSkipsTemporaryDeferral(t *testing.T) {
	config := NewConfig()
	ips := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}
	config.TemporarilyDeferredIPs = []string{"8.8.8.8"}
	selected, err := selectTargetAddrWithIPFilterBypass(config, ips, 80, false)
	require.NoError(t, err)
	require.True(t, selected.IP.Equal(ips[1]))
	selected, err = selectTargetAddrWithIPFilterBypass(config, ips, 80, true)
	require.NoError(t, err)
	require.True(t, selected.IP.Equal(ips[0]))
}
