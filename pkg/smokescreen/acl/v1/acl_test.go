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

			d, err := acl.Decide(testCase.service, testCase.host)
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

	d, err := acl.Decide("unk", "example.com")
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

func TestACLAddInvalidDomain(t *testing.T) {
	a := assert.New(t)

	acl := &ACL{
		Rules: make(map[string]Rule),
	}

	r := Rule{
		Project:     "security",
		Policy:      Open,
		DomainGlobs: []string{"*.*.stripe.com"},
	}

	a.Error(acl.Add("acl", r))
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
