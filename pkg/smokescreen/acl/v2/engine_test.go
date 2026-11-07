package acl

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecide(t *testing.T) {
	e, err := Load(Options{}, filepath.Join("testdata", "acl_sample.yaml"))
	require.NoError(t, err)

	tests := []struct {
		name, service, host, proxy string
		result                     DecisionResult
		reason                     string
		mitm                       bool
	}{
		{"service allow overrides a global deny", "ci", "pypi.org", "", Allow, "host matched allowed domain in rule", true},
		{"global deny without an override", "web", "pypi.org", "", Deny, "host matched rule in global deny list", false},
		{"global deny label wildcard", "audit", "registry.npmjs.org", "", Deny, "host matched rule in global deny list", false},
		{"global deny crosses public suffixes", "audit", "backup.s3.amazonaws.com", "", Deny, "host matched rule in global deny list", false},
		{"service deny beats a global allow", "web", "img.cdn.example.org", "", Deny, "host matched denied domain in rule", false},
		{"global allow for other services", "audit", "img.cdn.example.org", "", Allow, "host matched rule in global allow list", false},
		{"open action", "ci", "unlisted.example.org", "", Allow, "rule has open enforcement policy", false},
		{"report action", "audit", "unlisted.example.org", "", AllowAndReport, "rule has allow and report policy", false},
		{"allow entry crosses public suffixes when marked", "audit", "sts.s3.amazonaws.com", "", Allow, "host matched allowed domain in rule", false},
		{"enforce action with public suffix hint", "web", "access-analyzer.s3.amazonaws.com", "", Deny,
			"rule has enforce policy; wildcard 'access-analyzer.*.amazonaws.com' was not applied because 's3.amazonaws.com' is on the public suffix list", false},
		{"default service entry", "nobody", "status.example.com", "", Allow, "host matched allowed domain in rule", false},
		{"default service action", "nobody", "unlisted.example.org", "", Deny, "default rule policy used", false},
		{"proxy not allowed", "web", "www.example.com", "proxy.example.net", Deny, "connect proxy host not allowed in rule", false},
		{"proxy allowed", "ci", "pypi.org", "proxy.example.net", Allow, "host matched allowed domain in rule", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := e.Decide(DecideArgs{Service: tt.service, Host: tt.host, ConnectProxyHost: tt.proxy})
			require.NoError(t, err)
			assert.Equal(t, tt.result, d.Result)
			assert.Equal(t, tt.reason, d.Reason)
			assert.Equal(t, tt.mitm, d.MitmConfig != nil)
		})
	}

	none, err := Compile(&Policy{Version: Version}, Options{})
	require.NoError(t, err)
	d, err := none.Decide(DecideArgs{Service: "nobody", Host: "example.com"})
	require.NoError(t, err)
	assert.Equal(t, Decision{Result: Deny, Reason: "no rule matched"}, d)
}

// TestMitmSurvivesAnEarlierPlainEntry covers the shape that a translation
// from a v1 ACL produces: a plain entry for all the service's domains, then a
// separate entry per domain that has a MITM config. The plain entry matches
// first and has no Mitm of its own; the MITM config must still be found.
func TestMitmSurvivesAnEarlierPlainEntry(t *testing.T) {
	e, err := Compile(&Policy{
		Version: Version,
		Services: []Service{{
			Name: "ci", Action: ModeOpen,
			Allow: []Entry{
				{Domains: []string{"pypi.org", "slack.com"}},
				{Domains: []string{"slack.com"}, Mitm: &MitmConfig{AddHeaders: map[string]string{"X-A": "1"}}},
			},
		}},
	}, Options{})
	require.NoError(t, err)

	d, err := e.Decide(DecideArgs{Service: "ci", Host: "slack.com"})
	require.NoError(t, err)
	require.NotNil(t, d.MitmConfig)
	assert.Equal(t, "1", d.MitmConfig.AddHeaders["X-A"])
}

// TestDecisionMitmConfigIsNotShared guards against the MitmConfig on one
// Decision aliasing the Engine's own copy, or another Decision's copy: a
// caller that mutates one must never affect the others.
func TestDecisionMitmConfigIsNotShared(t *testing.T) {
	e, err := Compile(&Policy{
		Version: Version,
		Services: []Service{{
			Name: "web", Action: ModeEnforce,
			Allow: []Entry{{
				Domains: []string{"example.com"},
				Mitm: &MitmConfig{
					AddHeaders:                  map[string]string{"X-A": "1"},
					DetailedHttpLogsFullHeaders: []string{"User-Agent"},
				},
			}},
		}},
	}, Options{})
	require.NoError(t, err)

	d1, err := e.Decide(DecideArgs{Service: "web", Host: "example.com"})
	require.NoError(t, err)
	d1.MitmConfig.AddHeaders["X-A"] = "mutated"
	d1.MitmConfig.DetailedHttpLogsFullHeaders[0] = "mutated"

	d2, err := e.Decide(DecideArgs{Service: "web", Host: "example.com"})
	require.NoError(t, err)
	assert.Equal(t, "1", d2.MitmConfig.AddHeaders["X-A"], "mutating one decision's MitmConfig changed a later one")
	assert.Equal(t, "User-Agent", d2.MitmConfig.DetailedHttpLogsFullHeaders[0])
}

// TestUnmarkedOverlap covers a service allow entry that overlaps the global
// deny list without OverrideGlobalPolicy. Compat mode keeps v1's behavior and
// allows it. Otherwise Validate rejects the policy, and Decide also denies the
// request on its own, since Validate's overlap check is a static
// approximation; newEngine skips Validate to simulate an overlap it missed.
func TestUnmarkedOverlap(t *testing.T) {
	p := &Policy{
		Version: Version,
		Services: []Service{{
			Name: "web", Action: ModeEnforce,
			Allow: []Entry{{Domains: []string{"malicious.com"}}},
		}},
		Global: Global{Deny: []string{"malicious.com"}},
	}
	args := DecideArgs{Service: "web", Host: "malicious.com"}

	compat, err := Compile(p, Options{Compat: true})
	require.NoError(t, err)
	d, err := compat.Decide(args)
	require.NoError(t, err)
	assert.Equal(t, Allow, d.Result)

	require.Error(t, p.Validate(Options{}))
	d, err = newEngine(p, false).Decide(args)
	require.NoError(t, err)
	assert.Equal(t, Deny, d.Result)
	assert.Equal(t, "host matched rule in global deny list", d.Reason)
}
