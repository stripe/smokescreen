package metrics

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// metrics contains all of the metric names contained within the smokescreen package.
// These are used to determine if a given metric name is valid before associating
// a persistent tag with the metric. This list must be updated with new metric names
// if the metric should support persistent tagging.
var metrics = []string{
	// ACL decision statistics
	"acl.allow",
	"acl.decide_error",
	"acl.deny",
	"acl.report",
	"acl.role_not_determined",
	"acl.unknown_error",

	// Connection statistics (cn.atpt == connection attempt)
	"cn.atpt.total",        // Total connection attempts, tagged by success
	"cn.atpt.connect.err",  // Connection failures, tagged by failure type
	"cn.atpt.connect.time", // Connect time in ms, tagged by domain
	// The following are only emitted if Smokescreen is configured to use a ConnSuccessRateTracker.
	"cn.atpt.distinct_domains",              // Number of distinct domains seen by ConnSuccessRateTracker in computation window
	"cn.atpt.distinct_domains_success_rate", // Domain connection success rate computed by ConnSuccessRateTracker

	// DNS resolution statistics
	"resolver.allow.default",
	"resolver.allow.user_configured",
	"resolver.attempts_total",
	"resolver.deny.not_global_unicast",
	"resolver.deny.private_range",
	"resolver.deny.user_configured",
	"resolver.lookup_time", // DNS lookup time in ms, not tagged
	"resolver.errors_total",
}

type MetricsClientInterface interface {
	AddMetricTags(string, map[string]string) error
	Incr(string, float64) error
	IncrWithTags(string, map[string]string, float64) error
	Gauge(string, float64, float64) error
	Histogram(string, float64, float64) error
	HistogramWithTags(string, float64, map[string]string, float64) error
	Timing(string, time.Duration, float64) error
	TimingWithTags(string, time.Duration, map[string]string, float64) error
	SetStarted()
}

// reportConnError emits a detailed metric about a connection error, with a tag corresponding to
// the failure type. If err is not a net.Error, does nothing.
func ReportConnError(mc MetricsClientInterface, err error) {
	e, ok := err.(net.Error)
	if !ok {
		return
	}

	errorTag := map[string]string{"type": "unknown"}
	switch {
	case e.Timeout():
		errorTag["type"] = "timeout"
	case errors.Is(e, syscall.ECONNREFUSED):
		errorTag["type"] = "refused"
	case errors.Is(e, syscall.ECONNRESET):
		errorTag["type"] = "reset"
	case errors.Is(e, syscall.ECONNABORTED):
		errorTag["type"] = "aborted"
	}

	mc.IncrWithTags("cn.atpt.connect.err", errorTag, 1)
}
