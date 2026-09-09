//go:build !nounit
// +build !nounit

package smokescreen

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allowRanges = []string{
	"8.8.9.0/24",
	"10.0.1.0/24",
	"172.16.1.0/24",
	"192.168.1.0/24",
	"127.0.1.0/24",
}
var allowAddresses = []string{
	"10.0.0.1:321",
}
var denyRanges = []string{
	"1.1.1.1/32",
}
var denyAddresses = []string{
	"8.8.8.8:321",
}

type testCase struct {
	ip       string
	port     int
	expected ipType
}

func TestClassifyAddr(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	a.NoError(conf.SetDenyRanges(denyRanges))
	a.NoError(conf.SetDenyAddresses(denyAddresses))
	a.NoError(conf.SetAllowRanges(allowRanges))
	a.NoError(conf.SetAllowAddresses(allowAddresses))
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"
	conf.Port = 4750
	conf.LocalIPs = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.1.100"),
		net.ParseIP("::1"),
	}

	testIPs := []testCase{
		testCase{"8.8.8.8", 1, ipAllowDefault},
		testCase{"8.8.9.8", 1, ipAllowUserConfigured},

		// Specific blocked networks
		testCase{"10.0.0.1", 1, ipDenyPrivateRange},
		testCase{"10.0.0.1", 321, ipAllowUserConfigured},
		testCase{"10.0.1.1", 1, ipAllowUserConfigured},
		testCase{"172.16.0.1", 1, ipDenyPrivateRange},
		testCase{"172.16.1.1", 1, ipAllowUserConfigured},
		testCase{"192.168.0.1", 1, ipDenyPrivateRange},
		testCase{"192.168.1.1", 1, ipAllowUserConfigured},

		// CGNAT blocked networks (RFC 6598)
		testCase{"100.64.0.1", 1, ipDenyCGNAT},
		testCase{"100.64.0.100", 1, ipDenyCGNAT},
		testCase{"100.127.255.254", 1, ipDenyCGNAT},
		testCase{"100.63.255.254", 1, ipAllowDefault}, // Just outside CGNAT range
		testCase{"100.128.0.1", 1, ipAllowDefault},    // Just outside CGNAT range

		testCase{"8.8.8.8", 321, ipDenyUserConfigured},
		testCase{"1.1.1.1", 1, ipDenyUserConfigured},

		// localhost
		testCase{"127.0.0.1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"::1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.0.1.1", 1, ipAllowUserConfigured},

		// ec2 metadata endpoint
		testCase{"169.254.169.254", 1, ipDenyNotGlobalUnicast},

		// Broadcast addresses
		testCase{"255.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"ff02:0:0:0:0:0:0:2", 1, ipDenyNotGlobalUnicast},

		// IPv6 embedding schemes (RFC 6052, RFC 3056, RFC 4380, RFC 4291)
		// NAT64 well-known prefix (64:ff9b::/96) - embeds IPv4 in last 32 bits
		testCase{"64:ff9b::ac1c:5", 1, ipDenyIPv6Embedding},    // 172.28.0.5
		testCase{"64:ff9b::c000:201", 1, ipDenyIPv6Embedding},  // 192.0.2.1
		testCase{"64:ff9b::a00:1", 1, ipDenyIPv6Embedding},     // 10.0.0.1
		testCase{"64:ff9b::808:808", 1, ipDenyIPv6Embedding},   // 8.8.8.8 (public IP in NAT64)
		testCase{"64:ff9b::ffff:ffff", 1, ipDenyIPv6Embedding}, // 255.255.255.255 in NAT64
		// 6to4 prefix (2002::/16) - embeds IPv4 in bits 16-47
		testCase{"2002:c000:201::1", 1, ipDenyIPv6Embedding}, // 192.0.2.1
		testCase{"2002:a00:1::1", 1, ipDenyIPv6Embedding},    // 10.0.0.1
		testCase{"2002:808:808::1", 1, ipDenyIPv6Embedding},  // 8.8.8.8
		// Teredo prefix (2001::/32) - embeds IPv4 addresses
		testCase{"2001:0:4136:e378:8000:63bf:3fff:fdd2", 1, ipDenyIPv6Embedding},
		testCase{"2001:0:1234:5678:9abc:def0:1234:5678", 1, ipDenyIPv6Embedding},

		testCase{"2001:4860:4860::8888", 1, ipAllowDefault}, // Google DNS (not embedding)
		testCase{"2606:4700:4700::1111", 1, ipAllowDefault}, // Cloudflare DNS
		testCase{"64:ff9c::1", 1, ipAllowDefault},           // Outside NAT64 /96 prefix

		// Self-connection detection
		testCase{"127.0.0.1", 4750, ipDenySelfConnection},
		testCase{"192.168.1.100", 4750, ipDenySelfConnection},
		testCase{"::1", 4750, ipDenySelfConnection},
		testCase{"127.0.0.1", 8080, ipDenyNotGlobalUnicast}, // Different port
		testCase{"8.8.8.8", 4750, ipAllowDefault},           // Different IP
	}

	for _, test := range testIPs {
		localIP := net.ParseIP(test.ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", test.ip)
			continue
		}
		localAddr := net.TCPAddr{
			IP:   localIP,
			Port: test.port,
		}

		got := classifyAddr(conf, &localAddr)
		if got != test.expected {
			t.Errorf("Misclassified IP (%s:%d): should be %s, but is instead %s.", localIP, test.port, test.expected, got)
		}
	}
}

func TestInitializeSelfConnectionDetection(t *testing.T) {
	r := require.New(t)

	// Save original function and restore after test
	originalGetNetInterfaces := getNetInterfaces
	defer func() {
		getNetInterfaces = originalGetNetInterfaces
	}()

	// Test 1: Empty interfaces - should not error but config.LocalIPs should be empty
	getNetInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{}, nil
	}

	config, err := testConfig("allow-all")
	r.NoError(err)
	err = config.InitializeSelfConnectionDetection()
	r.NoError(err, "should not error even with no interfaces")
	r.NotNil(config.LocalIPs)
	r.Empty(config.LocalIPs, "should have empty LocalIPs when no interfaces")

	// Test 2: Error getting interfaces - should return error
	getNetInterfaces = func() ([]net.Interface, error) {
		return nil, errors.New("mock error getting interfaces")
	}

	config, err = testConfig("allow-all")
	r.NoError(err)
	err = config.InitializeSelfConnectionDetection()
	r.Error(err, "should error when getNetInterfaces fails")
	r.Contains(err.Error(), "failed to get local IPs for self-connection detection")
	r.Nil(config.LocalIPs)

	// Test 3: Normal operation - restore real function
	getNetInterfaces = originalGetNetInterfaces
	config, err = testConfig("allow-all")
	r.NoError(err)
	err = config.InitializeSelfConnectionDetection()
	r.NoError(err)
	r.NotEmpty(config.LocalIPs)

	hasLoopback := false
	for _, ip := range config.LocalIPs {
		if ip.IsLoopback() {
			hasLoopback = true
			break
		}
	}
	r.True(hasLoopback, "should have at least one loopback IP")
}

func TestAddrIsTemporarilyDeferred(t *testing.T) {
	tests := []struct {
		name                   string
		temporarilyDeferredIPs []string
		testIP                 string
		testPort               int
		expected               bool
	}{
		{
			name:                   "IP in deferred list",
			temporarilyDeferredIPs: []string{"192.168.1.1", "10.0.0.1"},
			testIP:                 "192.168.1.1",
			testPort:               80,
			expected:               true,
		},
		{
			name:                   "IP not in deferred list",
			temporarilyDeferredIPs: []string{"192.168.1.1", "10.0.0.1"},
			testIP:                 "192.168.1.2",
			testPort:               80,
			expected:               false,
		},
		{
			name:                   "Empty deferred list",
			temporarilyDeferredIPs: []string{},
			testIP:                 "192.168.1.1",
			testPort:               80,
			expected:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := &net.TCPAddr{
				IP:   net.ParseIP(tt.testIP),
				Port: tt.testPort,
			}
			result := addrIsTemporarilyDeferred(tt.temporarilyDeferredIPs, addr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSelectTargetAddr(t *testing.T) {
	tests := []struct {
		name                   string
		ips                    []string
		port                   int
		temporarilyDeferredIPs []string
		allowRanges            []string
		denyRanges             []string
		expectedIP             string
		expectError            bool
		errorContains          string
	}{
		{
			name:        "Select first allowed IP",
			ips:         []string{"8.8.8.8", "8.8.4.4"},
			port:        80,
			expectedIP:  "8.8.8.8",
			expectError: false,
		},
		{
			name:                   "Defer first IP, select second",
			ips:                    []string{"8.8.8.8", "8.8.4.4"},
			port:                   80,
			temporarilyDeferredIPs: []string{"8.8.8.8"},
			expectedIP:             "8.8.4.4",
			expectError:            false,
		},
		{
			name:                   "All IPs deferred, use fallback with priority",
			ips:                    []string{"8.8.8.8", "8.8.4.4"},
			port:                   80,
			temporarilyDeferredIPs: []string{"8.8.4.4", "8.8.8.8"},
			expectedIP:             "8.8.4.4", // Should select first in deferred list
			expectError:            false,
		},
		{
			name:          "All IPs denied",
			ips:           []string{"192.168.1.1", "10.0.0.1"},
			port:          80,
			expectError:   true,
			errorContains: "no valid IP found among resolved addresses",
		},
		{
			name:          "Empty IP list",
			ips:           []string{},
			port:          80,
			expectError:   true,
			errorContains: "no IP addresses to evaluate",
		},
		{
			name:        "Allow private ranges with allowed IP",
			ips:         []string{"192.168.1.1", "8.8.8.8"},
			port:        80,
			allowRanges: []string{"192.168.1.0/24"},
			expectedIP:  "192.168.1.1",
			expectError: false,
		},
		{
			name:        "Deny range blocks first IP, select second",
			ips:         []string{"1.1.1.1", "8.8.8.8"},
			port:        80,
			denyRanges:  []string{"1.1.1.0/24"},
			expectedIP:  "8.8.8.8",
			expectError: false,
		},
		{
			name:                   "Deny range forces fallback to deferred IP",
			ips:                    []string{"1.1.1.1", "8.8.8.8"},
			port:                   80,
			denyRanges:             []string{"1.1.1.0/24"},
			temporarilyDeferredIPs: []string{"8.8.8.8"},
			expectedIP:             "8.8.8.8", // First IP denied by deny range, must use deferred as fallback
			expectError:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test config
			config := NewConfig()
			config.Log = logrus.New()
			config.Log.SetLevel(logrus.DebugLevel)

			if len(tt.allowRanges) > 0 {
				err := config.SetAllowRanges(tt.allowRanges)
				require.NoError(t, err)
			}

			if len(tt.denyRanges) > 0 {
				err := config.SetDenyRanges(tt.denyRanges)
				require.NoError(t, err)
			}

			config.TemporarilyDeferredIPs = tt.temporarilyDeferredIPs

			// Convert string IPs to net.IP
			var ips []net.IP
			for _, ipStr := range tt.ips {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					ips = append(ips, ip)
				}
			}

			// Test the function
			selectedAddr, err := selectTargetAddr(config, ips, tt.port)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, selectedAddr)
				assert.Equal(t, tt.expectedIP, selectedAddr.IP.String())
				assert.Equal(t, tt.port, selectedAddr.Port)
			}
		})
	}
}

func TestSelectTargetAddrFallbackPriority(t *testing.T) {
	// Create a logger with a test hook
	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)

	config := NewConfig()
	config.Log = logger
	// Set deferred IPs in specific order to test priority
	config.TemporarilyDeferredIPs = []string{"8.8.4.4", "8.8.8.8"}

	// All IPs are deferred, should select based on priority in deferred list
	ips := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}

	selectedAddr, err := selectTargetAddr(config, ips, 80)

	require.NoError(t, err)
	// Should select 8.8.4.4 because it's first in the TemporarilyDeferredIPs list
	assert.Equal(t, "8.8.4.4", selectedAddr.IP.String())

	// Check that we have the fallback log entry
	entries := hook.AllEntries()

	var foundFallbackLog bool
	for _, entry := range entries {
		if entry.Data["reason"] == "all lookup IPs are in deferred list" && entry.Data["ip"] == "8.8.4.4" {
			foundFallbackLog = true
		}
	}

	assert.True(t, foundFallbackLog, "Should log fallback selection when all IPs are deferred")
}

func TestUnsafeAllowPrivateRanges(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	a.NoError(conf.SetDenyRanges([]string{"192.168.0.0/24", "10.0.0.0/8"}))
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"

	conf.UnsafeAllowPrivateRanges = true

	testIPs := []testCase{
		testCase{"8.8.8.8", 1, ipAllowDefault},

		// Specific blocked networks
		testCase{"10.0.0.1", 1, ipDenyUserConfigured},
		testCase{"10.0.0.1", 321, ipDenyUserConfigured},
		testCase{"10.0.1.1", 1, ipDenyUserConfigured},
		testCase{"172.16.0.1", 1, ipAllowDefault},
		testCase{"172.16.1.1", 1, ipAllowDefault},
		testCase{"192.168.0.1", 1, ipDenyUserConfigured},
		testCase{"192.168.1.1", 1, ipAllowDefault},

		// CGNAT blocked networks (RFC 6598) - should still be blocked even with UnsafeAllowPrivateRanges
		testCase{"100.64.0.1", 1, ipDenyCGNAT},
		testCase{"100.64.0.100", 1, ipDenyCGNAT},
		testCase{"100.127.255.254", 1, ipDenyCGNAT},

		// localhost
		testCase{"127.0.0.1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"::1", 1, ipDenyNotGlobalUnicast},

		// ec2 metadata endpoint
		testCase{"169.254.169.254", 1, ipDenyNotGlobalUnicast},

		// Broadcast addresses
		testCase{"255.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"ff02:0:0:0:0:0:0:2", 1, ipDenyNotGlobalUnicast},
	}

	for _, test := range testIPs {
		localIP := net.ParseIP(test.ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", test.ip)
			continue
		}
		localAddr := net.TCPAddr{
			IP:   localIP,
			Port: test.port,
		}

		got := classifyAddr(conf, &localAddr)
		if got != test.expected {
			t.Errorf("Misclassified IP (%s): should be %s, but is instead %s.", localIP, test.expected, got)
		}
	}

}

// TestClearsErrors tests that we are correctly preserving/removing the X-Smokescreen-Error header.
// This header is used to provide more granular errors to proxy clients, and signals that
// there was an issue connecting to the proxy target.
