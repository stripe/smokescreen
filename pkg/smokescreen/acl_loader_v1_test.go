// +build !nounit

package smokescreen

import "github.com/stretchr/testify/assert"
import (
	log "github.com/sirupsen/logrus"
	"testing"
)

var dummyConf = &Config{
	Log: log.New(),
}

func TestLoadFromYaml(t *testing.T) {
	a := assert.New(t)

	// Load a sane config
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/sample_config.yaml", []string{})
		a.Nil(err)
		a.NotNil(acl)
		a.Equal(4, len(acl.Services))
	}

	// Load a broken config
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/broken_config.yaml", []string{})
		a.NotNil(err)
		a.Nil(acl)
	}

	// Load a config that contains an unknown action
	{
		acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/unknown_action.yaml", []string{})
		a.Nil(err)
		a.NotNil(acl)
	}
}

func TestDecide(t *testing.T) {
	a := assert.New(t)

	acl, _ := LoadYamlAclFromFilePath(dummyConf, "testdata/sample_config.yaml", []string{})

	// Test allowed domain for enforcing service
	{
		res, err := acl.Decide("enforce-dummy-srv", "example1.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
	}
	{
		res, err := acl.Decide("enforce-dummy-srv", "www.example2.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionDeny, res)
	}
	{
		res, err := acl.Decide("enforce-dummy-srv", "example2.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
	}

	// Test disallowed domain for enforcing service
	{
		res, err := acl.Decide("enforce-dummy-srv", "www.example1.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionDeny, res)
	}

	// Test on reporting service
	{
		res, err := acl.Decide("report-dummy-srv", "example3.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
	}
	{
		res, err := acl.Decide("report-dummy-srv", "example1.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllowAndReport, res)
	}

	// Test on open service
	{
		res, err := acl.Decide("open-dummy-srv", "anythingisgoodreally.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
	}

	// Globbing
	{
		res, err := acl.Decide("dummy-glob", "shouldbreak.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionDeny, res)
	}
	{
		res, err := acl.Decide("dummy-glob", "example.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionDeny, res)
	}
	{
		res, err := acl.Decide("dummy-glob", "api.example.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
	}
}

func TestLoadYamlWithInvalidGlob(t *testing.T) {
	a := assert.New(t)

	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/contains_invalid_glob.yaml", []string{})
	a.Nil(err)
	a.Equal(0, len(acl.Services))
}

func TestLoadYamlWithInvalidMiddleGlob(t *testing.T) {
	a := assert.New(t)

	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/contains_middle_glob.yaml", []string{})
	a.Nil(err)
	a.Equal(0, len(acl.Services))
}

func TestLoadYamlWithDisabledAclAction(t *testing.T) {
	a := assert.New(t)
	acl, err := LoadYamlAclFromFilePath(dummyConf, "testdata/sample_config.yaml", []string{"enforce"})
	a.Nil(err)
	a.NotNil(acl)
	a.Equal(2, len(acl.Services))
	a.Nil(acl.Default)
}
