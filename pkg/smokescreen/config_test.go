package smokescreen

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetResolverAddressesRoundRobinsDial(t *testing.T) {
	addr1 := netListenPacket(t)
	addr2 := netListenPacket(t)

	conf := NewConfig()
	require.NoError(t, conf.SetResolverAddresses([]string{addr1, addr2}))

	dial := conf.Resolver.(*net.Resolver).Dial
	for i, want := range []string{addr1, addr2, addr1, addr2, addr1} {
		conn, err := dial(context.Background(), "udp", "192.0.2.1:53")
		require.NoError(t, err)
		assert.Equal(t, want, conn.RemoteAddr().String(), "dial %d", i)
		conn.Close()
	}
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
