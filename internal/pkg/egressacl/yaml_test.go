package egressacl

import "github.com/stretchr/testify/assert"
import "github.com/stripe/smokescreen/pkg/egressacl/decision"
import "testing"

func TestLoadFromYaml(t *testing.T) {
	assert := assert.New(t)

	// Load a sane config
	{
		acl, err := LoadFromYamlFile("testdata/sample_config.yaml")
		assert.Nil(err)
		assert.NotNil(acl)
		assert.Equal(3, len(acl.Services))
	}

	// Load a broken config
	{
		acl, err := LoadFromYamlFile("testdata/broken_config.yaml")
		assert.NotNil(err)
		assert.Nil(acl)
	}

	// Load a config that contains an unknown action
	{
		acl, err := LoadFromYamlFile("testdata/unknown_action.yaml")
		assert.NotNil(err)
		assert.Nil(acl)
	}
}

func TestDecide(t *testing.T) {
	assert := assert.New(t)

	acl, _ := LoadFromYamlFile("testdata/sample_config.yaml")

	// Test allowed domain for enforcing service
	{
		res, err := acl.Decide("enforce-dummy-srv", "example1.com")
		assert.Nil(err)
		assert.Equal(decision.ALLOW, res)
	}
	{
		res, err := acl.Decide("enforce-dummy-srv", "www.example2.com")
		assert.Nil(err)
		assert.Equal(decision.ALLOW, res)
	}
	{
		res, err := acl.Decide("enforce-dummy-srv", "example2.com")
		assert.Nil(err)
		assert.Equal(decision.ALLOW, res)
	}

	// Test disallowed domain for enforcing service
	{
		res, err := acl.Decide("enforce-dummy-srv", "www.example1.com")
		assert.Nil(err)
		assert.Equal(decision.DENY, res)
	}

	// Test on reporting service
	{
		res, err := acl.Decide("report-dummy-srv", "example3.com")
		assert.Nil(err)
		assert.Equal(decision.ALLOW, res)
	}
	{
		res, err := acl.Decide("report-dummy-srv", "example1.com")
		assert.Nil(err)
		assert.Equal(decision.ALLOW_REPORT, res)
	}

	// Test on open service
	{
		res, err := acl.Decide("open-dummy-srv", "anythingisgoodreally.com")
		assert.Nil(err)
		assert.Equal(decision.ALLOW, res)
	}
}
