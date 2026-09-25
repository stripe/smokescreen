package cmd

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfigurationWithoutResolverAddressUsesSystemResolver(t *testing.T) {
	conf, err := NewConfiguration([]string{"smokescreen"}, nil)
	require.NoError(t, err)

	r, ok := conf.Resolver.(*net.Resolver)
	require.True(t, ok, "expected *net.Resolver, got %T", conf.Resolver)
	require.Nil(t, r.Dial)
	require.False(t, r.PreferGo)
}

func TestNewConfigurationAcceptsSingleResolverAddress(t *testing.T) {
	conf, err := NewConfiguration([]string{
		"smokescreen",
		"--resolver-address", "127.0.0.1:5353",
	}, nil)
	require.NoError(t, err)

	r, ok := conf.Resolver.(*net.Resolver)
	require.True(t, ok, "expected *net.Resolver, got %T", conf.Resolver)
	require.NotNil(t, r.Dial, "custom resolver should dial the configured address")
	require.True(t, r.PreferGo)
}

func TestNewConfigurationAcceptsMultipleResolverAddresses(t *testing.T) {
	conf, err := NewConfiguration([]string{
		"smokescreen",
		"--resolver-address", "127.0.0.1:5353",
		"--resolver-address", "127.0.0.2:5353",
	}, nil)
	require.NoError(t, err)

	r, ok := conf.Resolver.(*net.Resolver)
	require.True(t, ok, "expected *net.Resolver, got %T", conf.Resolver)
	require.NotNil(t, r.Dial, "custom resolver should dial the configured addresses")
	require.True(t, r.PreferGo)
}

func TestNewConfigurationRejectsInvalidResolverAddress(t *testing.T) {
	conf, err := NewConfiguration([]string{
		"smokescreen",
		"--resolver-address", "127.0.0.1:5353",
		"--resolver-address", "127.0.0.2",
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid resolver address")
	require.Nil(t, conf)
}

func TestNewConfigurationAcceptsMultipleResolverAddressesFromConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(
		"resolver_addresses:\n  - 127.0.0.1:5353\n  - 127.0.0.2:5353\n",
	), 0o600))

	conf, err := NewConfiguration([]string{"smokescreen", "--config-file", path}, nil)
	require.NoError(t, err)

	r, ok := conf.Resolver.(*net.Resolver)
	require.True(t, ok, "expected *net.Resolver, got %T", conf.Resolver)
	require.NotNil(t, r.Dial, "custom resolver should dial the configured addresses")
	require.True(t, r.PreferGo)
}
