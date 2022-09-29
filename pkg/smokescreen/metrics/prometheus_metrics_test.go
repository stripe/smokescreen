package metrics

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMapKeys(t *testing.T) {
	r := require.New(t)

	inputMap := map[string]string{
		"firstKey":  "firstValue",
		"secondKey": "secondValue",
		"thirdKey":  "thirdValue",
	}

	expectedKeys := []string{
		"firstKey",
		"secondKey",
		"thirdKey",
	}

	r.Equal(expectedKeys, mapKeys(inputMap))
}

func TestMergeMaps(t *testing.T) {
	r := require.New(t)

	inputLeftMap := map[string]string{
		"firstLeftKey":  "firstLeftValue",
		"secondLeftKey": "secondLeftValue",
		"thirdLeftKey":  "thirdLeftValue",
	}

	inputRightMap := map[string]string{
		"firstRightKey":  "firstRightValue",
		"secondRightKey": "secondRightValue",
		"thirdRightKey":  "thirdRightValue",
	}

	expectedMap := map[string]string{
		"firstLeftKey":   "firstLeftValue",
		"secondLeftKey":  "secondLeftValue",
		"thirdLeftKey":   "thirdLeftValue",
		"firstRightKey":  "firstRightValue",
		"secondRightKey": "secondRightValue",
		"thirdRightKey":  "thirdRightValue",
	}

	mergeMaps(inputLeftMap, inputRightMap)
	r.Equal(expectedMap, inputLeftMap)
}

func TestSanitisePrometheusMetricName(t *testing.T) {
	r := require.New(t)

	tables := []struct {
		inputMetricName    string
		expectedMetricName string
	}{
		{
			inputMetricName:    "acl.allow",
			expectedMetricName: "acl_allow",
		},
		{
			inputMetricName:    "cn.atpt.total",
			expectedMetricName: "cn_atpt_total",
		},
		{
			inputMetricName:    "resolver.errors_total",
			expectedMetricName: "resolver_errors_total",
		},
	}

	for _, table := range tables {
		r.Equal(table.expectedMetricName, sanitisePrometheusMetricName(table.inputMetricName))
	}
}
