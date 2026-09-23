//go:build !smokescreen_no_prometheus

package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

func TestNewConfigurationParsesAllCLIFlags(t *testing.T) {
	statsSocketDir := t.TempDir()
	metricsPort := unusedTCPPort(t)
	metricsEndpoint := "/metrics-cli-parsing-" + metricsPort
	conf, err := NewConfiguration([]string{
		"smokescreen",
		"--listen-ip=127.0.0.2",
		"--listen-port=8123",
		"--timeout=17s",
		"--proxy-protocol",
		"--deny-range=10.0.0.0/8",
		"--deny-range=2001:db8::/32",
		"--allow-range=192.0.2.0/24",
		"--deny-address=203.0.113.1:443",
		"--allow-address=198.51.100.2",
		"--egress-acl-file=testdata/sample_config.yaml",
		"--resolver-address=127.0.0.1:5353",
		"--expose-prometheus-metrics",
		"--prometheus-endpoint=" + metricsEndpoint,
		"--prometheus-listen-ip=127.0.0.1",
		"--prometheus-port=" + metricsPort,
		"--tls-server-bundle-file=testdata/pki/server-bundle.pem",
		"--tls-client-ca-file=testdata/pki/ca.pem",
		"--tls-crl-file=testdata/pki/crl.pem",
		"--additional-error-message-on-deny=custom deny message",
		"--stats-socket-dir=" + statsSocketDir,
		"--stats-socket-file-mode=300",
		"--unsafe-allow-private-ranges",
		"--upstream-http-proxy-addr=http://http-proxy.example:8080",
		"--upstream-https-proxy-addr=http://https-proxy.example:8443",
		"--max-concurrent-requests=7",
		"--max-request-rate=12.5",
		"--max-request-burst=17",
		"--max-concurrent-connect-tunnels=19",
		"--dns-timeout=23s",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, conf)

	require.Equal(t, "127.0.0.2", conf.Ip)
	require.Equal(t, uint16(8123), conf.Port)
	require.Equal(t, 17*time.Second, conf.ConnectTimeout)
	require.True(t, conf.SupportProxyProtocol)
	require.Equal(t, []string{"10.0.0.0/8:0", "2001:db8::/32:0", "203.0.113.1/32:443"}, ruleRanges(conf.DenyRanges))
	require.Equal(t, []string{"192.0.2.0/24:0", "198.51.100.2/32:0"}, ruleRanges(conf.AllowRanges))
	require.NotNil(t, conf.EgressACL)
	require.NotNil(t, conf.Resolver)
	require.IsType(t, &metrics.PrometheusMetricsClient{}, conf.MetricsClient)
	require.NotNil(t, conf.TlsConfig)
	require.Len(t, conf.CrlByAuthorityKeyId, 1)
	require.Equal(t, "custom deny message", conf.AdditionalErrorMessageOnDeny)
	require.Empty(t, conf.DisabledAclPolicyActions)
	require.Equal(t, statsSocketDir, conf.StatsSocketDir)
	require.Equal(t, os.FileMode(0o300), conf.StatsSocketFileMode)
	require.True(t, conf.UnsafeAllowPrivateRanges)
	require.Equal(t, "http://http-proxy.example:8080", conf.UpstreamHttpProxyAddr)
	require.Equal(t, "http://https-proxy.example:8443", conf.UpstreamHttpsProxyAddr)
	require.Equal(t, 7, conf.MaxConcurrentRequests)
	require.Equal(t, 12.5, conf.MaxRequestRate)
	require.Equal(t, 17, conf.MaxRequestBurst)
	require.Equal(t, 19, conf.MaxConcurrentConnectTunnels)
	require.Equal(t, 23*time.Second, conf.DNSTimeout)
}

func TestNewConfigurationCLIParsingCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantNil    bool
		wantErr    string
		assertConf func(*testing.T, *smokescreen.Config)
	}{
		{
			name: "defaults",
			args: []string{"smokescreen"},
			assertConf: func(t *testing.T, conf *smokescreen.Config) {
				require.Equal(t, smokescreen.DefaultPort, conf.Port)
				require.Equal(t, smokescreen.DefaultConnectTimeout, conf.ConnectTimeout)
				require.Equal(t, smokescreen.DefaultDNSTimeout, conf.DNSTimeout)
			},
		},
		{
			name: "statsd address",
			args: []string{"smokescreen", "--statsd-address=127.0.0.1:8125"},
			assertConf: func(t *testing.T, conf *smokescreen.Config) {
				require.IsType(t, &metrics.StatsdMetricsClient{}, conf.MetricsClient)
			},
		},
		{
			name: "slice flags are repeatable and comma separated",
			args: []string{"smokescreen", "--disable-acl-policy-action=open", "--disable-acl-policy-action=report", "--disable-acl-policy-action=open,report"},
			assertConf: func(t *testing.T, conf *smokescreen.Config) {
				require.Equal(t, []string{"open", "report", "open", "report"}, conf.DisabledAclPolicyActions)
			},
		},
		{
			name:    "argument separator preserves positional argument behavior",
			args:    []string{"smokescreen", "--", "unexpected", "--listen-port=not-a-number"},
			wantNil: true,
			wantErr: "Received unexpected non-option argument(s)",
		},
		{
			name:    "invalid port range",
			args:    []string{"smokescreen", "--listen-port=65536"},
			wantNil: true,
			wantErr: "Invalid listen-port: 65536",
		},
		{
			name:    "invalid range",
			args:    []string{"smokescreen", "--allow-range=not-a-cidr"},
			wantNil: true,
			wantErr: "invalid CIDR address: not-a-cidr",
		},
		{
			name:    "invalid address",
			args:    []string{"smokescreen", "--deny-address=not-an-address"},
			wantNil: true,
			wantErr: "address must be in the form ip[:port], got not-an-address",
		},
		{
			name:    "unknown flag",
			args:    []string{"smokescreen", "--not-a-smokescreen-flag"},
			wantNil: true,
			wantErr: "flag provided but not defined: -not-a-smokescreen-flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := NewConfiguration(tt.args, nil)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tt.wantNil {
				require.Nil(t, conf)
				return
			}
			require.NotNil(t, conf)
			if tt.assertConf != nil {
				tt.assertConf(t, conf)
			}
		})
	}
}

func TestNewConfigurationHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{
		{"smokescreen", "--help"},
		{"smokescreen", "--version"},
	} {
		conf, err := NewConfiguration(args, nil)
		require.NoError(t, err)
		require.Nil(t, conf)
	}
}

func TestNewConfigurationExplicitFalseVersionFlagUsesV3Behavior(t *testing.T) {
	for _, args := range [][]string{
		{"smokescreen", "--version=false"},
		{"smokescreen", "-v=false"},
	} {
		conf, err := NewConfiguration(args, nil)
		require.NoError(t, err)
		require.Nil(t, conf)
	}
}

func ruleRanges(ranges []smokescreen.RuleRange) []string {
	values := make([]string, 0, len(ranges))
	for _, ruleRange := range ranges {
		values = append(values, fmt.Sprintf("%s:%d", ruleRange.Net.String(), ruleRange.Port))
	}
	return values
}

func unusedTCPPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

func TestNewConfigurationConfigFileCLIOverride(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "smokescreen.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("connect_timeout: 33s\nunsafe_allow_private_ranges: true\n"), 0o600))

	conf, err := NewConfiguration([]string{
		"smokescreen",
		"--config-file=" + configPath,
		"--timeout=11s",
		"--unsafe-allow-private-ranges=false",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, 11*time.Second, conf.ConnectTimeout)
	require.False(t, conf.UnsafeAllowPrivateRanges)
}
