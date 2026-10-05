package smokescreen

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowFirstIPPolicy(t *testing.T) {
	config := NewConfig()
	require.NoError(t, config.SetAllowRanges([]string{"10.0.0.0/24"}))
	require.NoError(t, config.SetDenyAddresses([]string{"10.0.0.5", "8.8.8.8", "127.0.0.1"}))
	policy := allowFirstIPPolicy{}
	for _, tt := range []struct {
		ip   string
		want ipType
	}{
		{"10.0.0.5", ipAllowUserConfigured},
		{"8.8.8.8", ipDenyUserConfigured},
		{"127.0.0.1", ipDenyNotGlobalUnicast},
		{"10.1.0.1", ipDenyPrivateRange},
		{"1.1.1.1", ipAllowDefault},
	} {
		t.Run(tt.ip, func(t *testing.T) {
			require.Equal(t, tt.want, policy.classify(config, &net.TCPAddr{IP: net.ParseIP(tt.ip), Port: 443}))
		})
	}
}

func TestMostSpecificIPPolicy(t *testing.T) {
	tests := []struct {
		name, allow, deny, ip string
		port                  int
		want                  ipType
	}{
		{"narrow deny", "10.0.0.0/24", "10.0.0.5", "10.0.0.5", 443, ipDenyUserConfigured},
		{"narrow allow", "10.0.0.5:443", "10.0.0.0/8", "10.0.0.5", 443, ipAllowUserConfigured},
		{"deny port", "10.0.0.5", "10.0.0.5:443", "10.0.0.5", 443, ipDenyUserConfigured},
		{"allow port", "10.0.0.5:443", "10.0.0.5", "10.0.0.5", 443, ipAllowUserConfigured},
		{"tie", "10.0.0.5:443", "10.0.0.5:443", "10.0.0.5", 443, ipDenyUserConfigured},
		{"CIDR address tie", "10.0.0.5/32", "10.0.0.5", "10.0.0.5", 443, ipDenyUserConfigured},
		{"other port", "10.0.0.5", "10.0.0.5:443", "10.0.0.5", 80, ipAllowUserConfigured},
		{"IPv6", "fd00::/64", "[fd00::5]:443", "fd00::5", 443, ipDenyUserConfigured},
		{"mapped tie", "::ffff:10.0.0.5/128", "10.0.0.5", "10.0.0.5", 443, ipDenyUserConfigured},
		{"mapped port", "::ffff:10.0.0.5/128", "10.0.0.5:443", "::ffff:10.0.0.5", 443, ipDenyUserConfigured},
		{"loopback", "127.0.0.0/8", "127.0.0.5", "127.0.0.5", 443, ipDenyUserConfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConfig()
			for _, entry := range []struct {
				value string
				rules *[]RuleRange
			}{{tt.allow, &c.AllowRanges}, {tt.deny, &c.DenyRanges}} {
				var rules []RuleRange
				var err error
				if _, _, e := net.ParseCIDR(entry.value); e == nil {
					rules, err = parseRanges([]string{entry.value})
				} else {
					rules, err = parseAddresses([]string{entry.value})
				}
				require.NoError(t, err)
				*entry.rules = rules
			}
			require.Equal(t, tt.want, mostSpecificIPPolicy{}.classify(c, &net.TCPAddr{IP: net.ParseIP(tt.ip), Port: tt.port}))
		})
	}
}

func TestMostSpecificIPPolicySafetyChecks(t *testing.T) {
	c := NewConfig()
	for _, tt := range []struct {
		ip   string
		want ipType
	}{{"10.0.0.1", ipDenyPrivateRange}, {"127.0.0.1", ipDenyNotGlobalUnicast}, {"100.64.0.1", ipDenyCGNAT}, {"64:ff9b::1", ipDenyIPv6Embedding}, {"8.8.8.8", ipAllowDefault}} {
		addr := &net.TCPAddr{IP: net.ParseIP(tt.ip), Port: 443}
		require.Equal(t, tt.want, mostSpecificIPPolicy{}.classify(c, addr))
		require.NoError(t, c.SetAllowAddresses([]string{tt.ip}))
		require.Equal(t, ipAllowUserConfigured, mostSpecificIPPolicy{}.classify(c, addr))
	}
}

func TestMostSpecificIPPolicyRuleOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		c := NewConfig()
		allows := []string{"10.0.0.0/8", "10.0.0.0/24"}
		denies := []string{"10.0.0.0/16", "10.0.0.0/25"}
		if reverse {
			allows[0], allows[1] = allows[1], allows[0]
			denies[0], denies[1] = denies[1], denies[0]
		}
		require.NoError(t, c.SetAllowRanges(append(allows, allows...)))
		require.NoError(t, c.SetDenyRanges(append(denies, denies...)))
		require.Equal(t, ipDenyUserConfigured, mostSpecificIPPolicy{}.classify(c, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}))
		require.Equal(t, ipAllowUserConfigured, mostSpecificIPPolicy{}.classify(c, &net.TCPAddr{IP: net.ParseIP("10.0.0.200"), Port: 443}))
	}
}

func TestIPRulePrecedenceDefaultsAndSelfConnections(t *testing.T) {
	c := NewConfig()
	require.False(t, c.MostSpecificIPRules)
	require.NoError(t, c.SetAllowRanges([]string{"10.0.0.0/24"}))
	require.NoError(t, c.SetDenyAddresses([]string{"10.0.0.5"}))
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}
	for _, mostSpecific := range []bool{false, true} {
		c.MostSpecificIPRules = mostSpecific
		require.NoError(t, c.Validate())
		want := ipAllowUserConfigured
		if mostSpecific {
			want = ipDenyUserConfigured
		}
		c.LocalIPs = nil
		c.AllowSelfConnections = false
		require.Equal(t, want, classifyAddr(c, addr, ""))
		c.LocalIPs = []net.IP{addr.IP}
		require.Equal(t, ipDenySelfConnection, classifyAddr(c, addr, ""))
		c.AllowSelfConnections = true
		require.Equal(t, want, classifyAddr(c, addr, ""))
	}
}

func TestIPRulePrecedenceHostnameBypass(t *testing.T) {
	for _, mostSpecific := range []bool{false, true} {
		c := NewConfig()
		c.MostSpecificIPRules = mostSpecific
		require.NoError(t, c.SetIPFilterBypassedDomains([]string{"*.internal.example.com"}))
		require.NoError(t, c.SetDenyAddresses([]string{"10.0.0.5"}))
		addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}
		require.Equal(t, ipDenyUserConfigured, classifyAddr(c, addr, "other.example.com"))
		require.Equal(t, ipAllowUserConfigured, classifyAddr(c, addr, "login.internal.example.com"))
		c.LocalIPs = []net.IP{addr.IP}
		require.Equal(t, ipDenySelfConnection, classifyAddr(c, addr, "login.internal.example.com"))
		c.AllowSelfConnections = true
		require.Equal(t, ipAllowUserConfigured, classifyAddr(c, addr, "login.internal.example.com"))
	}
}
