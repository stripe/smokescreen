package smokescreen

import (
	"fmt"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	log "github.com/sirupsen/logrus"
)

var metrics = map[string][]string{
	"acl.allow":                        []string{},
	"acl.decide_error":                 []string{},
	"acl.deny":                         []string{},
	"acl.report":                       []string{},
	"acl.role_not_determined":          []string{},
	"acl.unknown_error":                []string{},
	"cn.atpt.connect.time":             []string{},
	"cn.atpt.fail.total":               []string{},
	"cn.atpt.success.total":            []string{},
	"cn.atpt.total":                    []string{},
	"resolver.allow.default":           []string{},
	"resolver.allow.user_configured":   []string{},
	"resolver.attempts_total":          []string{},
	"resolver.deny.not_global_unicast": []string{},
	"resolver.deny.private_range":      []string{},
	"resolver.deny.user_configured":    []string{},
	"resolver.errors_total":            []string{},
}

type MetricsClient struct {
	additionalTags map[string][]string
	StatsdClient   statsd.ClientInterface
}

func NewMetricsClient(addr, namespace string) (*MetricsClient, error) {
	var client statsd.ClientInterface

	if addr == "" {
		log.Print("warn: no statsd address provided, using noop client")
		client = &statsd.NoOpClient{}
	} else {
		c, err := statsd.New(addr)
		if err != nil {
			return nil, err
		}
		c.Namespace = namespace
		client = c
	}

	return &MetricsClient{
		additionalTags: make(map[string][]string),
		StatsdClient:   client,
	}, nil
}

func NewNoopMetricsClient() *MetricsClient {
	return &MetricsClient{
		additionalTags: make(map[string][]string),
		StatsdClient:   &statsd.NoOpClient{},
	}
}

func (mc *MetricsClient) AddMetricTag(metric, tag string) error {
	if tags, ok := metrics[metric]; ok {
		metrics[metric] = append(tags, tag)
		return nil
	}
	return fmt.Errorf("unknown metric: %s", metric)
}

func (mc *MetricsClient) GetMetricTags(metric string) []string {
	if tags, ok := metrics[metric]; ok {
		return tags
	}
	return nil
}

func (mc *MetricsClient) Incr(metric string, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	return mc.StatsdClient.Incr(metric, mTags, rate)
}

func (mc *MetricsClient) IncrWithTags(metric string, tags []string, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	tags = append(tags, mTags...)
	return mc.StatsdClient.Incr(metric, tags, rate)
}

func (mc *MetricsClient) Timing(metric string, d time.Duration, rate float64) error {
	mTags := mc.GetMetricTags(metric)
	return mc.StatsdClient.Timing(metric, d, mTags, rate)
}

func (mc *MetricsClient) TimingWithTags(metric string, d time.Duration, rate float64, tags []string) error {
	mTags := mc.GetMetricTags(metric)
	tags = append(tags, mTags...)
	return mc.StatsdClient.Timing(metric, d, mTags, rate)
}
