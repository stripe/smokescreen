package hostport

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	for i, tt := range []struct {
		hostPort string
		host     string
		hostFQDN string
		port     int
		err      string
	}{
		{"127.0.0.1:1234", "127.0.0.1", "127.0.0.1", 1234, ""},
		{"example.net", "", "", NoPort, "missing port in address"},
		{"example.net:1337", "example.net", "example.net.", 1337, ""},
		{"example.net.:1337", "example.net.", "example.net.", 1337, ""},
		{"[example.net.]:1337", "example.net.", "example.net.", 1337, ""},
		{"[127.0.0.1]:1337", "127.0.0.1", "127.0.0.1", 1337, ""},
		{"[example.net]:1337", "example.net", "example.net.", 1337, ""},
		{"[[example.net]]:1337", "", "", NoPort, "missing port in address"},
		{"", "", "", NoPort, "missing port in address"},
		{":", "", "", NoPort, "invalid syntax"},
		{"::", "", "", NoPort, "too many colons in address"},
		{"2001:DB8::1337", "", "", NoPort, "too many colons in address"},
		{"[2001:DB8::1337]:1337", "2001:db8::1337", "2001:db8::1337", 1337, ""},
		{"[2001:DB8::1337]:91337", "2001:db8::1337", "2001:db8::1337", NoPort, "must be between 0 and 65535"},
		{"[2001:DB8::1337]:007", "2001:db8::1337", "2001:db8::1337", 7, ""},
		{"[2001:DB8::1337]:-12", "2001:db8::1337", "2001:db8::1337", NoPort, "must be between 0 and 65535"},
		{"[2001:DB8::1337]:https", "2001:db8::1337", "2001:db8::1337", NoPort, "invalid syntax"},
		{"🔐.example.com:123", "xn--jv8h.example.com", "xn--jv8h.example.com.", 123, ""},
		{"🔐.example.com:007", "xn--jv8h.example.com", "xn--jv8h.example.com.", 7, ""},
	} {
		t.Run(fmt.Sprintf("%d:%s", i+1, tt.hostPort), func(t *testing.T) {
			a := assert.New(t)
			hp, err := New(tt.hostPort, false)
			a.Equal(tt.host, hp.Host)
			a.Equal(tt.port, hp.Port)
			if tt.err != "" {
				a.ErrorContains(err, tt.err)
			} else {
				a.NoError(err)
			}
			// FQDN tests
			hp, err = New(tt.hostPort, true)
			a.Equal(tt.hostFQDN, hp.Host)
			a.Equal(tt.port, hp.Port)
			if tt.err == "" {
				a.NoError(err)
			} else {
				a.ErrorContains(err, tt.err)
			}
		})
	}
}

func TestNewWithScheme(t *testing.T) {
	var tests = []struct {
		scheme    string
		hostPort  string
		host      string
		port      int
		forceFQDN bool
		err       string
	}{
		{"http", "example.com", "example.com", 80, false, ""},
		{"http", "127.0.0.1", "127.0.0.1", 80, false, ""},
		{"https", "127.0.0.1:123", "127.0.0.1", 123, false, ""},
		{"https", "[2001:DB8::1337]", "", 443, false, "invalid domain \"[2001:DB8::1337]\": idna: disallowed rune U+005B"},
		{"https", "2001:DB8::1337", "2001:db8::1337", 443, false, ""},
		{"https", "[2001:DB8::1337]:443", "2001:db8::1337", 443, false, ""},
		{"https", "[2001:db8::1337]:443", "2001:db8::1337", 443, false, ""},
		{"https", "[2001:DB8::1337]:-1", "2001:DB8::1337", NoPort, false, "invalid port number -1: must be between 0 and 65535"},
		{"https", "[2001:db8::1337]:111111", "2001:db8::1337", NoPort, false, "invalid port number 111111: must be between 0 and 65535"},
		{"unknown", "[[2001:DB8::1337]]", "[[2001:DB8::1337]]", NoPort, false, "unable to determine port for unknown"},
		{"https", "🔐.example.com:123", "xn--jv8h.example.com", 123, false, ""},
		{"smtp", "✉️.example.com.", "xn--4bi.example.com.", 25, false, ""},
		{"https", "🔐.example.com:123", "xn--jv8h.example.com.", 123, true, ""},
		{"https", "🔐.example.com:007", "xn--jv8h.example.com.", 7, true, ""},
		{"https", "FOO-BAR.example.com", "foo-bar.example.com.", 443, true, ""},
		{"smtp", "✉️.example.com", "xn--4bi.example.com.", 25, true, ""},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("%v://%v", tt.scheme, tt.hostPort)
		t.Run(testname, func(t *testing.T) {
			r := require.New(t)

			hp, err := NewWithScheme(tt.hostPort, tt.scheme, tt.forceFQDN)
			r.Equal(tt.host, hp.Host)
			r.Equal(tt.port, hp.Port)

			if tt.err != "" {
				r.EqualError(err, tt.err)
			} else {
				r.NoError(err)
			}
		})
	}
}
