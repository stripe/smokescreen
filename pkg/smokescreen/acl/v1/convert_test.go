package acl

import (
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aclv2 "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
)

// TestEngineMatchesDecide checks that the converted engine decides every
// request exactly as v1 does, for every test ACL with and without wildcards
// across public suffixes, and for an ACL that exercises the precedence rules.
func TestEngineMatchesDecide(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var acls []*ACL
	for _, f := range []string{
		"acl_mitm_config.yaml",
		"acl_no_default.yaml",
		"acl_sample_config.yaml",
		"acl_sample_config_with_global.yaml",
		"acl_sample_default_bypass_config.yaml",
		"acl_unsafe_wildcards_across_public_suffixes.yaml",
	} {
		a, err := New(logger, NewYAMLLoader(filepath.Join("testdata", f)), nil)
		require.NoError(t, err, f)
		acls = append(acls, a)
	}
	acls = append(acls, &ACL{
		Rules: map[string]Rule{
			"ci": {
				Project: "ci", Policy: Open,
				DomainGlobs: []string{"pypi.org", "*.maven.org", "api*.example.com", "repo.maven.org"},
				// v1 uses the first MITM domain that matches, so repo.maven.org
				// gets the *.maven.org config.
				MitmDomains: []MitmDomain{
					{Domain: "*.maven.org", AddHeaders: map[string]string{"X": "1"}},
					{Domain: "repo.maven.org", AddHeaders: map[string]string{"X": "2"}},
					{Domain: "pypi.org", DetailedHttpLogs: true, DetailedHttpLogsFullHeaders: []string{"User-Agent"}},
				},
				ExternalProxyGlobs: []string{"proxy.example.net", "*.proxies.example.net"},
			},
			"web":   {Project: "web", Policy: Enforce, DomainGlobs: []string{"*.example.com", "access-analyzer.*.amazonaws.com"}},
			"audit": {Project: "audit", Policy: Report},
		},
		DefaultRule:     &Rule{Project: "default", Policy: Enforce, DomainGlobs: []string{"status.example.org"}},
		GlobalDenyList:  []string{"pypi.org", "*.maven.org", "regis*.npmjs.org", "access-analyzer.*.amazonaws.com"},
		GlobalAllowList: []string{"api.partner.example", "*.cdn.example.org", "img*.example.org"},
	})

	for i, a := range acls {
		for _, unsafe := range []bool{false, true} {
			a.UnsafeAllowWildcardsAcrossPublicSuffixes = unsafe
			e, err := a.Engine(aclv2.Options{})
			require.NoError(t, err, "acl %d unsafe=%v", i, unsafe)
			for _, args := range decideArgs(a) {
				want, wantErr := a.Decide(args)
				got, gotErr := e.Decide(aclv2.DecideArgs(args))
				require.Equal(t, wantErr != nil, gotErr != nil, "acl %d unsafe=%v %+v", i, unsafe, args)
				require.Equal(t, want, decisionFromV2(got), "acl %d unsafe=%v %+v", i, unsafe, args)
			}
		}
	}
}

// TestEngineRejects checks that Engine fails, rather than returning an engine
// that decides differently, when v2 cannot express the ACL, and that it keeps
// rejecting the ACL's disabled policies.
func TestEngineRejects(t *testing.T) {
	tests := []struct {
		name string
		acl  ACL
		err  string
	}{
		{
			name: "unknown policy",
			acl:  ACL{Rules: map[string]Rule{"web": {DomainGlobs: []string{"example.com"}}}},
			err:  "web: unknown policy",
		},
		{
			name: "rule for an empty service name",
			acl:  ACL{Rules: map[string]Rule{"": {Policy: Open}}},
			err:  "rule for an empty service name",
		},
		{
			name: "mitm domain that is not allowed",
			acl:  ACL{DefaultRule: &Rule{Policy: Enforce, DomainGlobs: []string{"example.com"}, MitmDomains: []MitmDomain{{Domain: "example.org"}}}},
			err:  `default: mitm domain "example.org" is not an allowed domain`,
		},
		{
			name: "label wildcard proxy across public suffixes",
			acl: ACL{
				Rules:                                    map[string]Rule{"ci": {Policy: Open, ExternalProxyGlobs: []string{"proxy.*.example.net"}}},
				UnsafeAllowWildcardsAcrossPublicSuffixes: true,
			},
			err: `ci: proxy glob "proxy.*.example.net" has a label wildcard`,
		},
		{
			name: "disabled policy",
			acl:  ACL{DefaultRule: &Rule{Policy: Open}, DisabledPolicies: []EnforcementPolicy{Open}},
			err:  "utilizes a disabled policy:Open",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.acl.Engine(aclv2.Options{})
			assert.ErrorContains(t, err, tt.err)
		})
	}
}

// decideArgs returns requests from every role, including an unknown one, for
// hosts and proxies derived from all of a's globs.
func decideArgs(a *ACL) []DecideArgs {
	var globs, proxies []string
	roles := []string{"", "no-such-role"}
	add := func(r Rule) {
		globs = append(globs, r.DomainGlobs...)
		proxies = append(proxies, r.ExternalProxyGlobs...)
	}
	for name, r := range a.Rules {
		roles = append(roles, name)
		add(r)
	}
	if a.DefaultRule != nil {
		add(*a.DefaultRule)
	}
	globs = append(append(globs, a.GlobalDenyList...), a.GlobalAllowList...)

	var args []DecideArgs
	for _, role := range roles {
		for _, host := range hostsFor(globs) {
			for _, proxy := range append([]string{""}, hostsFor(proxies)...) {
				args = append(args, DecideArgs{Service: role, Host: host, ConnectProxyHost: proxy})
			}
		}
	}
	return args
}

// hostsFor returns hosts that each glob matches or nearly matches: the glob's
// own name, subdomains, label variants, and its parent domain, plus hosts on
// public suffixes, IP addresses and IDN hosts.
func hostsFor(globs []string) []string {
	hosts := []string{
		"example.com", "unlisted.example.org", "foo.github.io", "x.s3.amazonaws.com", "access-analyzer.s3.amazonaws.com",
		"10.0.0.1", "127.0.0.1", "тест.example.com", "xn--e1aybc.example.com",
	}
	for _, g := range globs {
		base := strings.TrimPrefix(g, "*.")
		hosts = append(hosts, base, "a."+base, "a.b."+base, "x"+base, "A."+strings.ToUpper(base)+".")
		if strings.Contains(base, "*") {
			for _, fill := range []string{"x", "xy", "x.y", "", "s3"} {
				hosts = append(hosts, strings.Replace(base, "*", fill, 1))
			}
		}
		if i := strings.Index(base, "."); i >= 0 {
			hosts = append(hosts, base[i+1:], "a"+base[i:])
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

func decisionFromV2(d aclv2.Decision) Decision {
	out := Decision{Reason: d.Reason, Default: d.Default, Result: DecisionResult(d.Result), Project: d.Project}
	if d.MitmConfig != nil {
		out.MitmConfig = &MitmConfig{
			AddHeaders:                  d.MitmConfig.AddHeaders,
			DetailedHttpLogs:            d.MitmConfig.DetailedHttpLogs,
			DetailedHttpLogsFullHeaders: d.MitmConfig.DetailedHttpLogsFullHeaders,
		}
	}
	return out
}
