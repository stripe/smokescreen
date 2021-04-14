package smokescreen

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetricsTags(t *testing.T) {
	r := require.New(t)

	t.Run("add custom tags", func(t *testing.T) {
		metric := "acl.allow"
		mc := NewNoOpMetricsClient()

		err := mc.AddMetricTag(metric, "globalize")
		r.NoError(err)

		tags := mc.GetMetricTags(metric)
		r.Len(tags, 1)
		r.Equal(tags[0], "globalize")

		err = mc.AddMetricTag(metric, "ignore")
		r.NoError(err)

		tags = mc.GetMetricTags(metric)
		r.Len(tags, 2)
	})

	t.Run("add invalid tags", func(t *testing.T) {
		metric := "acl.does.not.exist"
		mc := NewNoOpMetricsClient()

		err := mc.AddMetricTag(metric, "globalize")
		r.Error(err)
	})
}

func TestMetricsClient(t *testing.T) {
	r := require.New(t)

	// Passing NewMetricsClient a missing statsd address should always fail
	t.Run("nil statsd addr", func(t *testing.T) {
		mc, err := NewMetricsClient("", "test_namespace")
		r.Error(err)
		r.Nil(mc)
	})
}
