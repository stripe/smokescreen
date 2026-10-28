package acl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostMatchesGlob(t *testing.T) {
	globs := map[string]struct {
		hostname string
		glob     string
		match    bool
	}{
		"simple match": {
			"example.com",
			"example.com",
			true,
		},
		"leading wildcard matches first component": {
			"contrived.example.com",
			"*.example.com",
			true,
		},
		"leading wildcard matches first two components": {
			"more.contrived.example.com",
			"*.example.com",
			true,
		},
		"wildcard after leading component": {
			"login.eu.example.com",
			"login.*.example.com",
			true,
		},
		"wildcard after leading component does not cross labels": {
			"login.a.b.example.com",
			"login.*.example.com",
			false,
		},
		"wildcard after leading component matches region": {
			"access-analyzer.us-west-2.amazonaws.com",
			"access-analyzer.*.amazonaws.com",
			true,
		},
		"wildcard after leading component does not match another registrable domain": {
			"access-analyzer.s3.amazonaws.com",
			"access-analyzer.*.amazonaws.com",
			false,
		},
		"trailing dot": {
			"example.com.",
			"example.com",
			true,
		},
		"uppercase host with lowercase glob": {
			"EXAMPLE.COM",
			"example.com",
			true,
		},
		"lowercase host with uppercase glob": {
			"example.com",
			"EXAMPLE.COM",
			true,
		},
		"empty hostname": {
			"",
			"example.com",
			false,
		},
		"label wildcard matches within label": {
			"api-east.example.com",
			"api*.example.com",
			true,
		},
		"label wildcard requires at least one character": {
			"api.example.com",
			"api*.example.com",
			false,
		},
		"label wildcard does not cross labels": {
			"api.evil.example.com",
			"api*.example.com",
			false,
		},
		"label wildcard does not match subdomains": {
			"a.api-east.example.com",
			"api*.example.com",
			false,
		},
		"label wildcard after leading component": {
			"web.qa-east.internal.example.com",
			"web.qa-*.internal.example.com",
			true,
		},
		"label wildcard with literal suffix": {
			"web42-canary.example.com",
			"web*-canary.example.com",
			true,
		},
		"label wildcard with uppercase host": {
			"API-EAST.EXAMPLE.COM.",
			"api*.example.com",
			true,
		},
	}

	a := assert.New(t)
	for name, g := range globs {
		t.Run(name, func(t *testing.T) {
			a.Equal(
				g.match,
				HostMatchesGlob(g.hostname, g.glob),
			)
		})
	}
}

func TestInvalidLabelWildcardNeverMatches(t *testing.T) {
	globs := map[string]string{
		"1*.0.0.1":          "10.0.0.1",
		"x.*.com":           "x.y.com",
		"foo*.github.io":    "foo1.github.io",
		"API*.example.com":  "api1.example.com",
		"xn--*.example.com": "xn--e1aybc.example.com",
	}
	for glob, host := range globs {
		t.Run(glob, func(t *testing.T) {
			require.Error(t, ValidateDomainGlob("svc", glob))
			assert.False(t, HostMatchesGlob(host, glob))
			assert.False(t, hostMatchesGlob(host, glob, false))
		})
	}
}

func TestIDNValidation(t *testing.T) {
	// Unicode domain should be rejected with punycode suggestion
	err := ValidateDomainGlob("test", "тест.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "use \"xn--e1aybc.example.com\"")

	// Punycode domain should be valid
	err = ValidateDomainGlob("test", "xn--e1aybc.example.com")
	assert.NoError(t, err)

	// Unicode with wildcard should be rejected
	err = ValidateDomainGlob("test", "*.тест.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "use \"*.xn--e1aybc.example.com\"")
}

func TestIDNHostMatching(t *testing.T) {
	// Unicode hostname should match punycode glob
	assert.True(t, HostMatchesGlob("тест.example.com", "xn--e1aybc.example.com"))

	// Punycode hostname should match unicode glob
	assert.True(t, HostMatchesGlob("xn--e1aybc.example.com", "тест.example.com"))

	// Wildcard matching with IDN
	assert.True(t, HostMatchesGlob("sub.тест.example.com", "*.xn--e1aybc.example.com"))
	assert.False(t, HostMatchesGlob("тест.example.com", "*.xn--e1aybc.example.com"))
}
