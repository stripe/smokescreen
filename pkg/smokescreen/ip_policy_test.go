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
