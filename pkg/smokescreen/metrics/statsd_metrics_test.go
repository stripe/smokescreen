package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMetricsTags(t *testing.T) {
	r := require.New(t)

	t.Run("add custom tags", func(t *testing.T) {
		metric := "acl.allow"
		mc := NewNoOpMetricsClient()

		err := mc.AddMetricTags(metric, map[string]string{"globalize": "value"})
		r.NoError(err)

		tags := mc.GetMetricTags(metric)
		r.Len(tags, 1)
		r.Equal(tags[0], "globalize:value")

		err = mc.AddMetricTags(metric, map[string]string{"ignore": "value"})
		r.NoError(err)

		tags = mc.GetMetricTags(metric)
		r.Len(tags, 2)
	})

	t.Run("add tags to a nonexistent metric", func(t *testing.T) {
		metric := "acl.does.not.exist"
		mc := NewNoOpMetricsClient()

		err := mc.AddMetricTags(metric, map[string]string{"globalize": "value"})
		r.Error(err)
	})
}

func TestMetricsClient(t *testing.T) {
	r := require.New(t)

	// Passing NewMetricsClient a missing statsd address should always fail
	t.Run("nil statsd addr", func(t *testing.T) {
		mc, err := NewStatsdMetricsClient("", "test_namespace")
		r.Error(err)
		r.Nil(mc)
	})

	// StatsdMetricsClient is not thread safe. Adding a tag after smokescreen has started
	// should always return an error.
	t.Run("adding metrics after started", func(t *testing.T) {
		mc := NewNoOpMetricsClient()
		mc.SetStarted()

		err := mc.AddMetricTags("acl.allow", map[string]string{"globalize": "value"})
		r.Error(err)
	})
}

func TestMockMetricsClient(t *testing.T) {
	r := require.New(t)

	t.Run("Incr", func(t *testing.T) {
		m := NewMockMetricsClient()
		m.Incr("foobar", 1)
		c, err := m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(1))
	})

	t.Run("Multiple Incr", func(t *testing.T) {
		m := NewMockMetricsClient()
		m.Incr("foobar", 1)
		m.Incr("foobar", 1)
		m.Incr("foobar", 1)
		c, err := m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(3))

		m.Incr("foobar", 123)
		c, err = m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(4))
	})

	t.Run("IncrWithTags", func(t *testing.T) {
		m := NewMockMetricsClient()
		tags := map[string]string{"foo": "value", "bar": "value"}
		m.IncrWithTags("foobar", tags, 1)
		/*c, err := m.GetCount("foobar", tags...)
		r.NoError(err)
		r.Equal(c, uint64(1))
		c, err = m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(1))*/
	})

	t.Run("Gauge", func(t *testing.T) {
		m := NewMockMetricsClient()
		m.Gauge("foobar", 2.0, 1)
		m.Gauge("foobar", 3.0, 1)
		c, err := m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(2))
		v, err := m.GetValues("foobar")
		r.NoError(err)
		r.Equal([]float64{2.0, 3.0}, v)
	})

	t.Run("Histogram", func(t *testing.T) {
		m := NewMockMetricsClient()
		m.Histogram("foobar", 2.0, 1)
		m.Histogram("foobar", 3.0, 1)
		c, err := m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(2))
		v, err := m.GetValues("foobar")
		r.NoError(err)
		r.Equal([]float64{2.0, 3.0}, v)
	})

	t.Run("HistogramWithTags", func(t *testing.T) {
		m := NewMockMetricsClient()
		tags := map[string]string{"foo": "value", "bar": "value"}
		m.HistogramWithTags("foobar", 2.0, tags, 1)
		/*c, err := m.GetCount("foobar", tags...)
		r.NoError(err)
		r.Equal(c, uint64(1))
		c, err = m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(1))
		v, err := m.GetValues("foobar")
		r.NoError(err)
		r.Equal([]float64{2.0}, v)
		v, err = m.GetValues("foobar", tags...)
		r.NoError(err)
		r.Equal([]float64{2.0}, v)*/
	})

	t.Run("Timing", func(t *testing.T) {
		m := NewMockMetricsClient()
		m.Timing("foobar", time.Second, 1)
		c, err := m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(1))
	})

	t.Run("TimingWithTags", func(t *testing.T) {
		m := NewMockMetricsClient()
		tags := map[string]string{"foo": "value", "bar": "value"}
		m.TimingWithTags("foobar", time.Second, 1, tags)
		/*c, err := m.GetCount("foobar", tags...)
		r.NoError(err)
		r.Equal(c, uint64(1))
		c, err = m.GetCount("foobar")
		r.NoError(err)
		r.Equal(c, uint64(1))*/
	})
}
