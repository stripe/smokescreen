package smokescreen

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetResolverAddressesSpreadsDialsAcrossAddresses(t *testing.T) {
	addr1 := netListenPacket(t)
	addr2 := netListenPacket(t)

	conf := NewConfig()
	require.NoError(t, conf.SetResolverAddresses([]string{addr1, addr2}))

	seen := map[string]int{}
	dial := conf.Resolver.(*net.Resolver).Dial
	for i := 0; i < 1000; i++ {
		conn, err := dial(context.Background(), "udp", "192.0.2.1:53")
		require.NoError(t, err)
		seen[conn.RemoteAddr().String()]++
		conn.Close()
	}

	assert.Len(t, seen, 2, "every dial must target a configured address: %v", seen)
	assert.GreaterOrEqual(t, seen[addr1], 400, "distribution: %v", seen)
	assert.GreaterOrEqual(t, seen[addr2], 400, "distribution: %v", seen)
}

func TestSetResolverAddressesSingleAddressAlwaysDialed(t *testing.T) {
	addr1 := netListenPacket(t)

	conf := NewConfig()
	require.NoError(t, conf.SetResolverAddresses([]string{addr1}))

	dial := conf.Resolver.(*net.Resolver).Dial
	for i := 0; i < 3; i++ {
		conn, err := dial(context.Background(), "udp", "192.0.2.1:53")
		require.NoError(t, err)
		assert.Equal(t, addr1, conn.RemoteAddr().String(), "dial %d", i)
		conn.Close()
	}
}

func netListenPacket(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l.LocalAddr().String()
}
