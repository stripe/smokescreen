package acl

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	aclv2 "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
)

// Policy returns an acl/v2 policy that decides every request the same way as
// a, for an ACL that passes v1 validation (as New guarantees). In v1 a
// service's allowed domains always win over the global deny list, so every
// converted service allow entry sets override_global_policy, and the policy
// compiles without aclv2.Options.Compat.
//
// Policy returns an error, rather than a policy that decides differently, when
// v2 cannot express a: a rule with an unknown policy, a rule for an empty
// service name, a MITM domain that is not one of its rule's allowed domains, or
// a proxy glob with a label wildcard in an ACL that allows wildcards across
// public suffixes, since v2 proxy globs never cross public suffixes.
func (a *ACL) Policy() (*aclv2.Policy, error) {
	p := &aclv2.Policy{Version: aclv2.Version}
	cross := a.UnsafeAllowWildcardsAcrossPublicSuffixes

	for _, name := range slices.Sorted(maps.Keys(a.Rules)) {
		if name == "" {
			return nil, errors.New("rule for an empty service name")
		}
		s, err := convertRule(a.Rules[name], cross)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		s.Name = name
		p.Services = append(p.Services, s)
	}
	if a.DefaultRule != nil {
		s, err := convertRule(*a.DefaultRule, cross)
		if err != nil {
			return nil, fmt.Errorf("default: %w", err)
		}
		p.Default = &s
	}

	p.Global.Deny = slices.Clone(a.GlobalDenyList)
	if len(a.GlobalAllowList) > 0 {
		p.Global.Allow = []aclv2.Entry{{Domains: slices.Clone(a.GlobalAllowList), CrossPublicSuffix: cross}}
	}
	return p, nil
}

// Engine compiles a's policy with a's disabled policies added to
// opts.DisabledModes, so that its decisions, reasons, projects and MITM configs
// match a.Decide. The engine is a snapshot: later changes to a do not reach it.
func (a *ACL) Engine(opts aclv2.Options) (*aclv2.Engine, error) {
	p, err := a.Policy()
	if err != nil {
		return nil, err
	}
	for _, policy := range a.DisabledPolicies {
		mode, err := convertPolicy(policy)
		if err != nil {
			return nil, err
		}
		opts.DisabledModes = append(opts.DisabledModes, mode)
	}
	return aclv2.Compile(p, opts)
}

// convertRule converts r into a v2 service without a name. Its allowed domains
// become one entry, followed by one entry per MITM domain in r's order, since
// v1 uses the first MITM domain that matches. Every MITM domain is also an
// allowed domain, so those entries allow nothing more. Every entry wins over
// the global deny list, as in v1.
func convertRule(r Rule, cross bool) (aclv2.Service, error) {
	action, err := convertPolicy(r.Policy)
	if err != nil {
		return aclv2.Service{}, err
	}
	s := aclv2.Service{Project: r.Project, Action: action, Proxies: slices.Clone(r.ExternalProxyGlobs)}
	if cross {
		for _, g := range r.ExternalProxyGlobs {
			if strings.Contains(strings.TrimPrefix(g, "*."), "*") {
				return aclv2.Service{}, fmt.Errorf("proxy glob %q has a label wildcard, which v2 cannot match across public suffixes", g)
			}
		}
	}
	if len(r.DomainGlobs) > 0 {
		s.Allow = append(s.Allow, aclv2.Entry{Domains: slices.Clone(r.DomainGlobs), CrossPublicSuffix: cross, OverrideGlobalPolicy: true})
	}
	for _, m := range r.MitmDomains {
		if !slices.Contains(r.DomainGlobs, m.Domain) {
			return aclv2.Service{}, fmt.Errorf("mitm domain %q is not an allowed domain", m.Domain)
		}
		s.Allow = append(s.Allow, aclv2.Entry{
			Domains:              []string{m.Domain},
			CrossPublicSuffix:    cross,
			OverrideGlobalPolicy: true,
			Mitm: &aclv2.MitmConfig{
				AddHeaders:                  maps.Clone(m.AddHeaders),
				DetailedHttpLogs:            m.DetailedHttpLogs,
				DetailedHttpLogsFullHeaders: slices.Clone(m.DetailedHttpLogsFullHeaders),
			},
		})
	}
	return s, nil
}

func convertPolicy(p EnforcementPolicy) (aclv2.Mode, error) {
	switch p {
	case Open:
		return aclv2.ModeOpen, nil
	case Report:
		return aclv2.ModeReport, nil
	case Enforce:
		return aclv2.ModeEnforce, nil
	}
	return aclv2.ModeUnknown, fmt.Errorf("unknown policy %v", p)
}
