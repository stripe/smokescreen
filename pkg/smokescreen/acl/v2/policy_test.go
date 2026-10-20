package acl

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecideSample(t *testing.T) {
	e, err := LoadFile(filepath.Join("testdata", "acl_v2_sample.yaml"), Options{})
	require.NoError(t, err)

	tests := []struct {
		name, role, host, proxy string
		result                  DecisionResult
		reason                  string
		mitm                    bool
	}{
		{"role allow overrides any deny", "ci", "pypi.org", "", Allow, "host matched allowed domain in rule", true},
		{"any deny applies without a role rule", "web", "pypi.org", "", Deny, "host matched rule in global deny list", false},
		{"deny crosses public suffix when the rule says so", "ci", "registry.npmjs.org", "", Deny, "host matched rule in global deny list", false},
		{"role deny beats any allow", "web", "img.cdn.example.org", "", Deny, "host matched denied domain in rule", false},
		{"any allow applies to other roles", "audit", "img.cdn.example.org", "", Allow, "host matched rule in global allow list", false},
		{"open mode", "ci", "unlisted.example.org", "", Allow, "rule has open enforcement policy", false},
		{"report mode", "audit", "unlisted.example.org", "", AllowAndReport, "rule has allow and report policy", false},
		{"enforce mode", "web", "unlisted.example.org", "", Deny, "rule has enforce policy", false},
		{"unknown role rule", "nobody", "status.example.com", "", Allow, "host matched allowed domain in rule", false},
		{"unknown role mode", "nobody", "unlisted.example.org", "", Deny, "default rule policy used", false},
		{"proxy not allowed", "web", "www.example.com", "proxy.example.net", Deny, "connect proxy host not allowed in rule", false},
		{"proxy allowed", "ci", "pypi.org", "proxy.example.net", Allow, "host matched allowed domain in rule", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := e.Decide(DecideArgs{Service: tt.role, Host: tt.host, ConnectProxyHost: tt.proxy})
			require.NoError(t, err)
			assert.Equal(t, tt.result, d.Result)
			assert.Equal(t, tt.reason, d.Reason)
			assert.Equal(t, tt.mitm, d.MitmConfig != nil)
		})
	}
}

func TestValidate(t *testing.T) {
	roles := []Role{{Name: "web", Mode: ModeEnforce}}
	deny := Rule{ID: "deny", Action: ActionDeny, Subjects: Subjects{Any: true}, Domains: []Domain{{Glob: "*.example.com"}}}
	allow := Rule{ID: "allow", Action: ActionAllow, Subjects: Subjects{Roles: []string{"web"}}, Domains: []Domain{{Glob: "api.example.com"}}}

	tests := []struct {
		name  string
		p     Policy
		opts  Options
		error string
	}{
		{"duplicate role", Policy{Roles: append(roles, roles[0])}, Options{}, `role "web" is defined more than once`},
		{"missing mode", Policy{Roles: []Role{{Name: "web"}}}, Options{}, "mode is required"},
		{"disabled mode", Policy{Roles: roles}, Options{DisabledModes: []Mode{ModeEnforce}}, "utilizes a disabled policy:Enforce"},
		{"duplicate rule id", Policy{Roles: roles, Rules: []Rule{deny, deny}}, Options{}, `rule id "deny" is used more than once`},
		{"undefined subject role", Policy{Rules: []Rule{allow}}, Options{}, `subject role "web" is not defined`},
		{"undefined unknown role", Policy{Rules: []Rule{{ID: "u", Action: ActionAllow, Subjects: Subjects{UnknownRole: true}, Domains: deny.Domains}}}, Options{}, "subject unknown_role is not defined"},
		{"two subject kinds", Policy{Roles: roles, Rules: []Rule{{ID: "x", Action: ActionAllow, Subjects: Subjects{Any: true, Roles: []string{"web"}}, Domains: deny.Domains}}}, Options{}, "exactly one of"},
		{"mitm on deny", Policy{Roles: roles, Rules: []Rule{{ID: "x", Action: ActionDeny, Subjects: Subjects{Roles: []string{"web"}}, Domains: deny.Domains, Mitm: &MitmConfig{}}}}, Options{}, "mitm is only allowed"},
		{"missing override", Policy{Roles: roles, Rules: []Rule{deny, allow}}, Options{}, `overlaps deny rule "deny"; add it to overrides`},
		{"override of unknown rule", Policy{Roles: roles, Rules: []Rule{func() Rule { r := allow; r.Overrides = []string{"nope"}; return r }()}}, Options{}, `overrides "nope"`},
		{"invalid glob", Policy{Roles: roles, Rules: []Rule{{ID: "x", Action: ActionAllow, Subjects: Subjects{Any: true}, Domains: []Domain{{Glob: "*"}}}}}, Options{}, "must not match everything"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Version = Version
			require.ErrorContains(t, tt.p.Validate(tt.opts), tt.error)
		})
	}

	ok := Policy{Version: Version, Roles: roles, Rules: []Rule{deny, func() Rule { r := allow; r.Overrides = []string{"deny"}; return r }()}}
	require.NoError(t, ok.Validate(Options{}))
}
