package metrics

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
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
