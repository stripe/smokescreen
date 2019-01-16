// +build !nounit

package smokescreen

import "github.com/stretchr/testify/assert"
import (
	"path"
	"testing"

	log "github.com/sirupsen/logrus"
)

var dummyConf = &Config{
	Log: log.New(),
}

var testCases = map[string]struct {
	yamlFile, service, host string
	expectDecision          EgressAclDecision
	expectProject           string
}{
	"allowed by list when enforcing": {
		"sample_config.yaml",
		"enforce-dummy-srv",
		"example1.com",
		EgressAclDecisionAllow,
		"usersec",
	},
	"disallowed when enforcing": {
		"sample_config.yaml",
		"enforce-dummy-srv",
		"www.example1.com",
		EgressAclDecisionDeny,
		"usersec",
	},
	"allowed by list when reporting": {
		"sample_config.yaml",
		"report-dummy-srv",
		"example3.com",
		EgressAclDecisionAllow,
		"security",
	},
	"reported when reporting": {
		"sample_config.yaml",
		"report-dummy-srv",
		"example1.com",
		EgressAclDecisionAllowAndReport,
		"security",
	},
	"allowed when open": {
		"sample_config.yaml",
		"open-dummy-srv",
		"anythingisgoodreally.com",
		EgressAclDecisionAllow,
		"automation",
	},
	"deny by glob": {
		"sample_config.yaml",
		"dummy-glob",
		"shouldbreak.com",
		EgressAclDecisionDeny,
		"phony",
	},
	"deny by glob missing subdomain": {
		"sample_config.yaml",
		"dummy-glob",
		"example.com",
		EgressAclDecisionDeny,
		"phony",
	},
	"allow by glob": {
		"sample_config.yaml",
		"dummy-glob",
		"api.example.com",
		EgressAclDecisionAllow,
		"phony",
	},
	"deny from default": {
		"sample_config.yaml",
		"unknown-service",
		"nope.example.com",
		EgressAclDecisionDeny,
		"other",
	},
	"allow from default list": {
		"sample_config.yaml",
		"unknown-service",
		"default.example.com",
		EgressAclDecisionAllow,
		"other",
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

			decision, _, err := acl.Decide(testCase.service, testCase.host)
			a.NoError(err)
			a.Equal(testCase.expectDecision, decision)
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

	decision, _, err := acl.Decide("unk", "example.com")
	a.Equal(EgressAclDecisionNoRuleDeny, decision)
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
