package metrics

import (
	"github.com/stretchr/testify/require"
	"sort"
	"testing"
)

func TestConstructTagArray(t *testing.T) {
	r := require.New(t)

	inputMap := map[string]string{
		"firstKey":  "firstValue",
		"secondKey": "secondValue",
		"thirdKey":  "thirdValue",
	}

	expectedTagArray := []string{
		"firstKey:firstValue",
		"secondKey:secondValue",
		"thirdKey:thirdValue",
	}

	actualTagArray := constructTagArray(inputMap)
	sort.Strings(actualTagArray)

	r.Equal(expectedTagArray, actualTagArray)
}