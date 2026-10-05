package metrics

type prometheusMetricDefinition struct {
	name    string
	help    string
	buckets []float64
}

var byteBuckets = []float64{1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864, 268435456}
var connectionDurationBuckets = []float64{1, 5, 15, 30, 60, 300, 900, 3600, 21600, 86400}

// Keys are internal StatsD names. Export names and units belong to this adapter.
var prometheusDefinitions = map[string]prometheusMetricDefinition{
	"resolver.deny.cgnat_range":              {"resolver_deny_cgnat_range_total", "Destinations denied for carrier grade NAT addresses.", nil},
	"resolver.deny.ipv6_embedding":           {"resolver_deny_ipv6_embedding_total", "Destinations denied for embedded IPv4 addresses.", nil},
	"resolver.deny.self_connection":          {"resolver_deny_self_connection_total", "Destinations denied for self connections.", nil},
	"cn.atpt.total":                          {"connection_attempts_total", "Connection attempts, tagged by success.", nil},
	"cn.atpt.connect.err":                    {"connection_errors_total", "Connection errors, tagged by type.", nil},
	"cn.close":                               {"connections_closed_total", "Closed tracked connections.", nil},
	"cn.bytes_in":                            {"connection_received_bytes", "Bytes received per closed tracked connection.", byteBuckets},
	"cn.bytes_out":                           {"connection_sent_bytes", "Bytes sent per closed tracked connection.", byteBuckets},
	"cn.duration":                            {"connection_duration_seconds", "Duration of closed tracked connections in seconds.", connectionDurationBuckets},
	"cn.atpt.connect.time":                   {"connection_connect_duration_seconds", "Destination connection establishment duration in seconds.", nil},
	"resolver.lookup_time":                   {"resolver_lookup_duration_seconds", "Destination resolution duration in seconds.", nil},
	"proxy_duration_ms":                      {"proxy_duration_seconds", "Elapsed request processing time before destination dialing in seconds.", nil},
	"cn.active_at_termination":               {"connections_active_at_termination_total", "Connections closed during shutdown.", nil},
	"cn.atpt.distinct_domains":               {"connection_distinct_domains", "Distinct domains in the success tracking window.", nil},
	"cn.atpt.distinct_domains_success_rate":  {"connection_distinct_domains_success_ratio", "Fraction of domains with successful connections in the tracking window.", nil},
	"acl.allow":                              {"acl_allow_total", "Allowed ACL decisions.", nil},
	"acl.deny":                               {"acl_deny_total", "Denied ACL decisions.", nil},
	"acl.report":                             {"acl_report_total", "Reported ACL decisions.", nil},
	"acl.decide_error":                       {"acl_decide_error_total", "ACL decision errors.", nil},
	"acl.role_not_determined":                {"acl_role_not_determined_total", "Requests without a determined role.", nil},
	"acl.unknown_error":                      {"acl_unknown_error_total", "Unknown ACL errors.", nil},
	"acl.upstream_proxy_parse_error":         {"acl_upstream_proxy_parse_error_total", "Upstream proxy parse errors.", nil},
	"resolver.allow.default":                 {"resolver_allow_default_total", "Destinations allowed by default IP policy.", nil},
	"resolver.allow.user_configured":         {"resolver_allow_user_configured_total", "Destinations allowed by configured IP policy.", nil},
	"resolver.attempts_total":                {"resolver_attempts_total", "Destination resolution attempts.", nil},
	"resolver.errors_total":                  {"resolver_errors_total", "Destination resolution errors.", nil},
	"resolver.deny.not_global_unicast":       {"resolver_deny_not_global_unicast_total", "Destinations denied for non global unicast addresses.", nil},
	"resolver.deny.private_range":            {"resolver_deny_private_range_total", "Destinations denied for private addresses.", nil},
	"resolver.deny.user_configured":          {"resolver_deny_user_configured_total", "Destinations denied by configured IP policy.", nil},
	"upstream_proxy_selector.proxy_selected": {"upstream_proxy_selector_proxy_selected_total", "Upstream proxy selections.", nil},
	"tunnels.concurrency_limited":            {"tunnels_concurrency_limited_total", "Tunnels rejected by concurrency limits.", nil},
	"requests.rate_limited":                  {"requests_rate_limited_total", "Requests rejected by rate limits.", nil},
	"requests.concurrency_limited":           {"requests_concurrency_limited_total", "Requests rejected by concurrency limits.", nil},
	"requests.concurrent":                    {"requests_concurrent", "Concurrent requests.", nil},
}
