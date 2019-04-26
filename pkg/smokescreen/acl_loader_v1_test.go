// +build !nounit

package smokescreen

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	log "github.com/sirupsen/logrus"
)

var dummyConf = &Config{
	Log: log.New(),
}

var testCases = map[string]struct {
	yamlFile, service, host string
	expectDecision          EgressAclDecision
	expectDecisionReason    string
	expectProject           string
}{
	"allowed by list when enforcing": {
		"sample_config.yaml",
		"enforce-dummy-srv",
		"example1.com",
		EgressAclDecisionAllow,
		"host matched allowed domain in rule",
		"usersec",
	},
	"disallowed when enforcing": {
		"sample_config.yaml",
		"enforce-dummy-srv",
		"www.example1.com",
		EgressAclDecisionDeny,
		"default rule used",
		"usersec",
	},
	"allowed by list when reporting": {
		"sample_config.yaml",
		"report-dummy-srv",
		"example3.com",
		EgressAclDecisionAllow,
		"host matched allowed domain in rule",
		"security",
	},
	"reported when reporting": {
		"sample_config.yaml",
		"report-dummy-srv",
		"example1.com",
		EgressAclDecisionAllowAndReport,
		"default rule used",
		"security",
	},
	"allowed when open": {
		"sample_config.yaml",
		"open-dummy-srv",
		"anythingisgoodreally.com",
		EgressAclDecisionAllow,
		"rule has open enforcement policy",
		"automation",
	},
	"deny by glob": {
		"sample_config.yaml",
		"dummy-glob",
		"shouldbreak.com",
		EgressAclDecisionDeny,
		"default rule used",
		"phony",
	},
	"deny by glob missing subdomain": {
		"sample_config.yaml",
		"dummy-glob",
		"example.com",
		EgressAclDecisionDeny,
		"default rule used",
		"phony",
	},
	"allow by glob": {
		"sample_config.yaml",
		"dummy-glob",
		"api.example.com",
		EgressAclDecisionAllow,
		"host matched allowed domain in rule",
		"phony",
	},
	"deny from default": {
		"sample_config.yaml",
		"unknown-service",
		"nope.example.com",
		EgressAclDecisionDeny,
		"default rule used",
		"other",
	},
	"allow from default list": {
		"sample_config.yaml",
		"unknown-service",
		"default.example.com",
		EgressAclDecisionAllow,
		"host matched allowed domain in rule",
		"other",
	},
	"allow from global allowlist enforce service": {
		"sample_config_with_global.yaml",
		"enforce-dummy-srv",
		"goodexample1.com",
		EgressAclDecisionAllow,
		"host matched rule in global allow list",
		"usersec",
	},
	"allow from global allowlist unknown service": {
		"sample_config_with_global.yaml",
		"unknown-service",
		"goodexample2.com",
		EgressAclDecisionAllow,
		"host matched rule in global allow list",
		"other",
	},
	"allow despite global denylist with allowed domains override": {
		"sample_config_with_global.yaml",
		"enforce-dummy-srv",
		"badexample1.com",
		EgressAclDecisionAllow,
		"host matched allowed domain in rule",
		"usersec",
	},
	"deny from global denylist report service": {
		"sample_config_with_global.yaml",
		"report-dummy-srv",
		"badexample1.com",
		EgressAclDecisionDeny,
		"host matched rule in global deny list",
		"security",
	},
	"deny from global denylist unknown service": {
		"sample_config_with_global.yaml",
		"unknown-service",
		"badexample2.com",
		EgressAclDecisionDeny,
		"host matched rule in global deny list",
		"other",
	},
	"deny from global denylist open service": {
		"sample_config_with_global.yaml",
		"open-dummy-srv",
		"badexample2.com",
		EgressAclDecisionDeny,
		"host matched rule in global deny list",
		"automation",
	},
	"deny from conflicting lists open service": {
		"sample_config_with_global.yaml",
		"open-dummy-srv",
		"conflictingexample.com",
		EgressAclDecisionDeny,
		"host matched rule in global deny list",
		"automation",
	},
}

func TestServiceDecideAndProject(t *testing.T) {
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			a := assert.New(t)
			acl, err := LoadYamlAclFromFilePath(dummyConf, path.Join("testdata", testCase.yamlFile))

			a.NoError(err)
			a.NotNil(acl)

			proj, err := acl.Project(testCase.service)
			a.NoError(err)
			a.Equal(testCase.expectProject, proj)

			decision, reason, _, err := acl.Decide(testCase.service, testCase.host)
			a.NoError(err)
			a.Equal(testCase.expectDecision, decision)
			a.Equal(testCase.expectDecisionReason, reason)
		})
	}
}

func TestUnknownServiceWithoutDefault(t *testing.T) {
	a := assert.New(t)
	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/no_default.yaml")

	a.NoError(err)
	a.NotNil(acl)

	proj, err := acl.Project("unk")
	a.Equal("unknown role: 'unk'", err.Error())
	a.Empty(proj)

	decision, _, usedDefaultRule, err := acl.Decide("unk", "example.com")
	a.Equal(EgressAclDecisionDeny, decision)
	a.False(usedDefaultRule)
	a.Nil(err)
}

func TestLoadFromYaml(t *testing.T) {
	a := assert.New(t)

	// Load a sane config
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/sample_config.yaml")
		a.Nil(err)
		a.NotNil(acl)
		a.Equal(4, len(acl.Services))
		a.Equal(0, len(acl.GlobalDenyList))
		a.Equal(0, len(acl.GlobalAllowList))
	}

	// Load a sane config with global lists
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/sample_config_with_global.yaml")
		a.Nil(err)
		a.NotNil(acl)
		a.Equal(4, len(acl.Services))
		a.Equal(3, len(acl.GlobalDenyList))
		a.Equal(4, len(acl.GlobalAllowList))
	}

	// Load a broken config
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/broken_config.yaml")
		a.NotNil(err)
		a.Nil(acl)
	}

	// Load a config that contains an unknown action
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/unknown_action.yaml")
		a.Nil(err)
		a.NotNil(acl)
	}
}

func TestLoadYamlWithInvalidGlob(t *testing.T) {
	a := assert.New(t)

	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/contains_invalid_glob.yaml")
	a.Nil(err)
	a.Equal(0, len(acl.Services))
}

func TestLoadYamlWithInvalidMiddleGlob(t *testing.T) {
	a := assert.New(t)

	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/contains_middle_glob.yaml")
	a.Nil(err)
	a.Equal(0, len(acl.Services))
}

func TestLoadYamlWithDisabledAclAction(t *testing.T) {
	a := assert.New(t)
	dummyConf.DisabledAclPolicyActions = []string{"enforce"}
	defer func() { dummyConf.DisabledAclPolicyActions = []string{} }()
	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/sample_config.yaml")
	a.Nil(err)
	a.NotNil(acl)
	a.Equal(2, len(acl.Services))
	a.Nil(acl.Default)
}
