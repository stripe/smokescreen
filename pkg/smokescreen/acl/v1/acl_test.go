//go:build !nounit
// +build !nounit

package acl

import (
	"path"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var testCases = map[string]struct {
	yamlFile, service, host string
	expectDecision          DecisionResult
	expectDecisionReason    string
	expectProject           string
}{
	"allowed by list when enforcing": {
		"sample_config.yaml",
		"enforce-dummy-srv",
		"example1.com",
		Allow,
		"host matched allowed domain in rule",
		"usersec",
	},
	"disallowed when enforcing": {
		"sample_config.yaml",
		"enforce-dummy-srv",
		"www.example1.com",
		Deny,
		"rule has enforce policy",
		"usersec",
	},
	"allowed by list when reporting": {
		"sample_config.yaml",
		"report-dummy-srv",
		"example3.com",
		Allow,
		"host matched allowed domain in rule",
		"security",
	},
	"reported when reporting": {
		"sample_config.yaml",
		"report-dummy-srv",
		"example1.com",
		AllowAndReport,
		"rule has allow and report policy",
		"security",
	},
	"allowed when open": {
		"sample_config.yaml",
		"open-dummy-srv",
		"anythingisgoodreally.com",
		Allow,
		"rule has open enforcement policy",
		"automation",
	},
	"deny by glob": {
		"sample_config.yaml",
		"dummy-glob",
		"shouldbreak.com",
		Deny,
		"rule has enforce policy",
		"phony",
	},
	"deny by glob missing subdomain": {
		"sample_config.yaml",
		"dummy-glob",
		"example.com",
		Deny,
		"rule has enforce policy",
		"phony",
	},
	"allow by glob": {
		"sample_config.yaml",
		"dummy-glob",
		"api.example.com",
		Allow,
		"host matched allowed domain in rule",
		"phony",
	},
	"deny from default": {
		"sample_config.yaml",
		"unknown-service",
		"nope.example.com",
		Deny,
		"default rule policy used",
		"other",
	},
	"allow from default list": {
		"sample_config.yaml",
		"unknown-service",
		"default.example.com",
		Allow,
		"host matched allowed domain in rule",
		"other",
	},
	"allow from global allowlist enforce service": {
		"sample_config_with_global.yaml",
		"enforce-dummy-srv",
		"goodexample1.com",
		Allow,
		"host matched rule in global allow list",
		"usersec",
	},
	"allow from global allowlist unknown service": {
		"sample_config_with_global.yaml",
		"unknown-service",
		"goodexample2.com",
		Allow,
		"host matched rule in global allow list",
		"other",
	},
	"allow despite global denylist with allowed domains override": {
		"sample_config_with_global.yaml",
		"enforce-dummy-srv",
		"badexample1.com",
		Allow,
		"host matched allowed domain in rule",
		"usersec",
	},
	"deny from global denylist report service": {
		"sample_config_with_global.yaml",
		"report-dummy-srv",
		"badexample1.com",
		Deny,
		"host matched rule in global deny list",
		"security",
	},
	"deny from global denylist unknown service": {
		"sample_config_with_global.yaml",
		"unknown-service",
		"badexample2.com",
		Deny,
		"host matched rule in global deny list",
		"other",
	},
	"deny from global denylist open service": {
		"sample_config_with_global.yaml",
		"open-dummy-srv",
		"badexample2.com",
		Deny,
		"host matched rule in global deny list",
		"automation",
	},
	"deny from global denylist trailing dot open service": {
		"sample_config_with_global.yaml",
		"open-dummy-srv",
		"badexample2.com.",
		Deny,
		"host matched rule in global deny list",
		"automation",
	},
	"deny from global denylist case mismatch open service": {
		"sample_config_with_global.yaml",
		"open-dummy-srv",
		"bAdExAmPlE2.cOm",
		Deny,
		"host matched rule in global deny list",
		"automation",
	},
	"deny from conflicting lists open service": {
		"sample_config_with_global.yaml",
		"open-dummy-srv",
		"conflictingexample.com",
		Deny,
		"host matched rule in global deny list",
		"automation",
	},
}

func TestACLDecision(t *testing.T) {
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			a := assert.New(t)

			yl := NewYAMLLoader(path.Join("testdata", testCase.yamlFile))
			acl, err := New(logrus.New(), yl, []string{})

			a.NoError(err)
			a.NotNil(acl)

			proj, err := acl.Project(testCase.service)
			a.NoError(err)
			a.Equal(testCase.expectProject, proj)

			d, err := acl.Decide(testCase.service, testCase.host, "")
			a.NoError(err)
			a.Equal(testCase.expectDecision, d.Result)
			a.Equal(testCase.expectDecisionReason, d.Reason)
		})
	}
}

func TestACLUnknownServiceWithoutDefault(t *testing.T) {
	a := assert.New(t)

	yl := NewYAMLLoader("testdata/no_default.yaml")
	acl, err := New(logrus.New(), yl, []string{})

	a.NoError(err)
	a.NotNil(acl)

	proj, err := acl.Project("unk")
	a.Equal("no rule for service: unk", err.Error())
	a.Empty(proj)

	d, err := acl.Decide("unk", "example.com", "")
	a.Equal(Deny, d.Result)
	a.False(d.Default)
	a.Nil(err)
}

func TestACLAddPolicyDisabled(t *testing.T) {
	a := assert.New(t)

	acl := &ACL{}

	acl.DisablePolicies([]string{"open"})
	r := Rule{
		Project:     "security",
		Policy:      Open,
		DomainGlobs: []string{"stripe.com"},
	}

	a.Error(acl.Add("acl", r))
}

func TestACLMalformedPolicyDisable(t *testing.T) {
	_, err := New(
		logrus.New(),
		NewYAMLLoader("testdata/no_default.yaml"), // any file will do
		[]string{"sillystring"},
	)
	assert.Error(t, err)
}

func TestACLAddInvalidGlob(t *testing.T) {
	invalidGlobs := map[string]struct {
		glob     string
		errorMsg string
	}{
		"multiple wildcards": {
			"*.*.stripe.com",
			"domain globs are only supported as prefix",
		},
		"matches everything (*)": {
			"*",
			"domain glob must not match everything",
		},
		"matches everything (*.)": {
			"*.",
			"domain glob must not match everything",
		},
		"non-normalized domain": {
			"éxämple.com",
			"incorrect ACL entry; use \"xn--xmple-gra7a.com\"",
		},
	}

	acl := &ACL{
		Rules: make(map[string]Rule),
	}

	for name, g := range invalidGlobs {
		t.Run(name, func(t *testing.T) {
			a := assert.New(t)

			err := acl.Add("acl", Rule{
				Project:     "security",
				Policy:      Open,
				DomainGlobs: []string{g.glob},
			})

			a.ErrorContains(err, g.errorMsg)
		})
	}
}

func TestACLAddExistingRule(t *testing.T) {
	a := assert.New(t)

	acl := &ACL{
		Rules: make(map[string]Rule),
	}
	svc := "stripe"

	r := Rule{
		Project:     "security",
		Policy:      Open,
		DomainGlobs: []string{"*.stripe.com"},
	}

	a.NoError(acl.Add(svc, r))
	a.Error(acl.Add(svc, r))
}

// TestHostMatchesGlob tests that hostnames and variants match as expected against domain globs.
// Does not test hostnames against globs that do not conform to the glob policy of
// ACL.ValidateDomainGlobs(), as these would already have been rejected during ACL validation.
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

func TestMitmComfig(t *testing.T) {
	a := assert.New(t)

	yl := NewYAMLLoader(path.Join("testdata", "mitm_config.yaml"))
	acl, err := New(logrus.New(), yl, []string{})

	a.NoError(err)
	a.NotNil(acl)

	mitmService := "enforce-dummy-mitm-srv"

	proj, err := acl.Project(mitmService)
	a.NoError(err)
	a.Equal("usersec", proj)

	d, err := acl.Decide(mitmService, "example-mitm.com", "")
	a.NoError(err)
	a.Equal(Allow, d.Result)
	a.Equal("host matched allowed domain in rule", d.Reason)

	a.NotNil(d.MitmConfig)
	a.Equal(true, d.MitmConfig.DetailedHttpLogs)
	a.Equal([]string{"User-Agent"}, d.MitmConfig.DetailedHttpLogsFullHeaders)
	a.Equal(map[string]string{"Accept-Language": "el"}, d.MitmConfig.AddHeaders)
}

func TestInvalidMitmComfig(t *testing.T) {
	a := assert.New(t)

	acl := &ACL{
		Rules: map[string]Rule{
			"enforce-dummy-mitm-srv": {
				Project: "usersec",
				Policy:  Enforce,
				DomainGlobs: []string{
					"example.com",
				},
				MitmDomains: []MitmDomain{{
					Domain: "example-mitm.com",
					AddHeaders: map[string]string{
						"Accept-Language": "el",
					},
					DetailedHttpLogs: true,
				}},
			},
		},
	}

	err := acl.Validate()
	a.Error(err)
}
