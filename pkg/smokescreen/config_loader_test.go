package smokescreen

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func loadYAMLForTest(t *testing.T, cfg *Config, contents string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return cfg.LoadFile(path)
}

func TestLoadFilePreservesUnsetSettings(t *testing.T) {
	cfg := NewConfig()
	cfg.Port = 9999
	cfg.Ip = "127.0.0.2"
	cfg.Network = "ip4"
	cfg.ConnectTimeout = 7 * time.Second
	cfg.ReadTimeout = 8 * time.Second
	cfg.UpstreamHttpProxyAddr = "http://proxy.example:8080"
	cfg.UpstreamHttpsProxyAddr = "https://proxy.example:8443"
	cfg.AddServerIpHeader = true
	cfg.TemporarilyDeferredIPs = []string{"1.1.1.1"}
	cfg.AllowMissingRole = true
	cfg.UnsafeAllowPrivateRanges = true
	cfg.SupportProxyProtocol = true
	cfg.MaxConcurrentConnectTunnels = 3
	require.NoError(t, cfg.SetAllowRanges([]string{"10.0.0.0/8"}))
	require.NoError(t, cfg.SetRateLimits(5, 10, 30))
	want := *cfg
	want.IdleTimeout = 4 * time.Second
	require.NoError(t, loadYAMLForTest(t, cfg, "idle_timeout: 4s\n"))
	require.Equal(t, want, *cfg)
}

func TestLoadFileAppliesExplicitZeroValues(t *testing.T) {
	cfg := NewConfig()
	cfg.Ip = "127.0.0.2"
	cfg.AllowMissingRole = true
	cfg.SupportProxyProtocol = true
	cfg.UnsafeAllowPrivateRanges = true
	cfg.MaxConcurrentConnectTunnels = 4
	require.NoError(t, cfg.SetRateLimits(5, 10, 30))
	require.NoError(t, loadYAMLForTest(t, cfg, `
ip: ""
port: 0
allow_missing_role: false
support_proxy_protocol: false
unsafe_allow_private_ranges: false
connect_timeout: 0s
read_header_timeout: 0s
read_timeout: 0s
write_timeout: 0s
max_concurrent_requests: 0
max_request_rate: 0
max_request_burst: 0
max_concurrent_connect_tunnels: 0
`))
	require.Empty(t, cfg.Ip)
	require.Zero(t, cfg.Port)
	require.False(t, cfg.AllowMissingRole)
	require.False(t, cfg.SupportProxyProtocol)
	require.False(t, cfg.UnsafeAllowPrivateRanges)
	require.Zero(t, cfg.ConnectTimeout)
	require.Zero(t, cfg.ReadHeaderTimeout)
	require.Zero(t, cfg.ReadTimeout)
	require.Zero(t, cfg.WriteTimeout)
	require.Zero(t, cfg.MaxConcurrentRequests)
	require.Zero(t, cfg.MaxRequestRate)
	require.Zero(t, cfg.MaxRequestBurst)
	require.Zero(t, cfg.MaxConcurrentConnectTunnels)
}

func TestLoadFileReplacesRules(t *testing.T) {
	for _, prefix := range []string{"allow", "deny"} {
		for _, suffix := range []string{"ranges", "addresses"} {
			t.Run(prefix+"_"+suffix, func(t *testing.T) {
				cfg := NewConfig()
				require.NoError(t, cfg.SetAllowRanges([]string{"10.0.0.0/8"}))
				require.NoError(t, cfg.SetAllowAddresses([]string{"198.51.100.1"}))
				require.NoError(t, cfg.SetDenyRanges([]string{"172.16.0.0/12"}))
				require.NoError(t, cfg.SetDenyAddresses([]string{"203.0.113.1"}))
				rules, other := &cfg.AllowRanges, &cfg.DenyRanges
				if prefix == "deny" {
					rules, other = other, rules
				}
				unchanged := append([]RuleRange(nil), (*other)...)
				value, want := "192.0.2.0/24", "192.0.2.0/24"
				if suffix == "addresses" {
					value, want = "192.0.2.1", "192.0.2.1/32"
				}
				key := prefix + "_" + suffix
				for i := 0; i < 2; i++ {
					require.NoError(t, loadYAMLForTest(t, cfg, key+": ["+value+"]\n"))
					require.Len(t, *rules, 1, "either key replaces both caller ranges and addresses")
					require.Equal(t, want, (*rules)[0].Net.String())
					require.Equal(t, unchanged, *other)
				}
				require.NoError(t, loadYAMLForTest(t, cfg, key+": []\n"))
				require.Empty(t, *rules)
				require.Equal(t, unchanged, *other)
			})
		}
	}
}

func TestLoadFileCombinesFileRulesAndAllowsCallerExtensions(t *testing.T) {
	cfg := NewConfig()
	require.NoError(t, loadYAMLForTest(t, cfg, "allow_ranges: [192.0.2.0/24]\nallow_addresses: [198.51.100.1]\n"))
	require.NoError(t, cfg.SetAllowAddresses([]string{"203.0.113.1"}))
	require.Len(t, cfg.AllowRanges, 3)
	require.Equal(t, "192.0.2.0/24", cfg.AllowRanges[0].Net.String())
	require.Equal(t, "198.51.100.1/32", cfg.AllowRanges[1].Net.String())
	require.Equal(t, "203.0.113.1/32", cfg.AllowRanges[2].Net.String())
}

func TestLoadFileBurstAloneDoesNotEnableLimiting(t *testing.T) {
	cfg := NewConfig()
	require.NoError(t, loadYAMLForTest(t, cfg, "max_request_burst: 5\n"))
	require.Equal(t, 5, cfg.MaxRequestBurst)
	require.Zero(t, cfg.MaxRequestRate)
	require.Zero(t, cfg.MaxConcurrentRequests)
	handler := NewRateLimitedHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), cfg)
	for i := 0; i < 10; i++ {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.com", nil))
		require.Equal(t, http.StatusNoContent, response.Code)
	}
}

func TestLoadFileRateLimitDefaultsAndPartialUpdate(t *testing.T) {
	cfg := NewConfig()
	require.NoError(t, loadYAMLForTest(t, cfg, "max_request_rate: 10\n"))
	require.Equal(t, 20, cfg.MaxRequestBurst)
	require.NoError(t, loadYAMLForTest(t, cfg, "max_concurrent_requests: 3\n"))
	require.Equal(t, float64(10), cfg.MaxRequestRate)
	require.Equal(t, 20, cfg.MaxRequestBurst)
	require.Equal(t, 3, cfg.MaxConcurrentRequests)
}

func TestLoadFileRejectsUnknownKeysBeforeApplyingSettings(t *testing.T) {
	cfg := NewConfig()
	cfg.Port = 9999
	require.Error(t, loadYAMLForTest(t, cfg, "port: 1234\nunknown_key: true\n"))
	require.Equal(t, uint16(9999), cfg.Port)
}

func TestLoadFileReturnsInvalidSocketMode(t *testing.T) {
	cfg := NewConfig()
	err := loadYAMLForTest(t, cfg, "stats_socket_file_mode: invalid\n")
	require.ErrorContains(t, err, "invalid stats_socket_file_mode")
	var parseErr *strconv.NumError
	require.ErrorAs(t, err, &parseErr)
	require.Equal(t, os.FileMode(DefaultStatsSocketFileMode), cfg.StatsSocketFileMode)
}
