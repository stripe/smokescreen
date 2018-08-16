// +build !nounit

package smokescreen

import "github.com/stretchr/testify/assert"
import "testing"

func TestLoadFromYaml(t *testing.T) {
	a := assert.New(t)

	// Load a sane config
	{
		acl, err := LoadFromYamlFile("testdata/sample_config.yaml")
		a.Nil(err)
		a.NotNil(acl)
		a.Equal(3, len(acl.Services))
	}

	// Load a broken config
	{
		acl, err := LoadFromYamlFile("testdata/broken_config.yaml")
		a.NotNil(err)
		a.Nil(acl)
	}

	// Load a config that contains an unknown action
	{
		acl, err := LoadFromYamlFile("testdata/unknown_action.yaml")
		a.NotNil(err)
		a.Nil(acl)
	}
}

func TestDecide(t *testing.T) {
	a := assert.New(t)

	acl, _ := LoadFromYamlFile("testdata/sample_config.yaml")

	// Test allowed domain for enforcing service
	{
		res, err := acl.Decide("enforce-dummy-srv", "example1.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
	}
	{
		res, err := acl.Decide("enforce-dummy-srv", "www.example2.com")
		a.Nil(err)
		a.Equal(EgressAclDecisionAllow, res)
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
}
