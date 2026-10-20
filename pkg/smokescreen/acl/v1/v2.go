package acl

import (
	"fmt"
	"slices"

	aclv2 "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
)

// Rule IDs that ToV2 gives to the global lists.
const (
	GlobalDenyRuleID  = "v1/global_deny_list"
	GlobalAllowRuleID = "v1/global_allow_list"
)

// ToV2 translates the ACL into a v2 policy that makes the same decisions.
//
// The translation writes down what v1 leaves implicit:
//   - Each service becomes a role, and the default rule becomes the unknown role.
//   - A rule's allowed domains become a role-scoped allow rule, and each MITM
//     domain becomes a role-scoped allow rule with its MITM config.
//   - The global lists become any-scoped rules. The deny list matches across
//     public suffixes, as it always did in v1.
//   - A role-scoped rule that overlaps the global deny list lists it in
//     Overrides, because v1 checks a service's own domains first.
//
// MITM domains that are missing from allowed domains are dropped. Validate
// rejects them, so this only affects ACLs that were never validated.
func (acl *ACL) ToV2() *aclv2.Policy {
	cross := acl.UnsafeAllowWildcardsAcrossPublicSuffixes
	p := &aclv2.Policy{Version: aclv2.Version}

	names := make([]string, 0, len(acl.Rules))
	for name := range acl.Rules {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		r := acl.Rules[name]
		p.Roles = append(p.Roles, v2Role(name, r, cross))
		p.Rules = append(p.Rules, v2Rules("v1/services/"+name, aclv2.Subjects{Roles: []string{name}}, r, cross)...)
	}
	if acl.DefaultRule != nil {
		u := v2Role("", *acl.DefaultRule, cross)
		p.UnknownRole = &u
		p.Rules = append(p.Rules, v2Rules("v1/default", aclv2.Subjects{UnknownRole: true}, *acl.DefaultRule, cross)...)
	}

	if len(acl.GlobalDenyList) > 0 {
		p.Rules = append(p.Rules, aclv2.Rule{
			ID:       GlobalDenyRuleID,
			Action:   aclv2.ActionDeny,
			Subjects: aclv2.Subjects{Any: true},
			Domains:  v2Domains(acl.GlobalDenyList, true),
		})
	}
	if len(acl.GlobalAllowList) > 0 {
		p.Rules = append(p.Rules, aclv2.Rule{
			ID:       GlobalAllowRuleID,
			Action:   aclv2.ActionAllow,
			Subjects: aclv2.Subjects{Any: true},
			Domains:  v2Domains(acl.GlobalAllowList, cross),
		})
	}

	p.AddOverrides()
	return p
}

func v2Role(name string, r Rule, cross bool) aclv2.Role {
	return aclv2.Role{
		Name:    name,
		Project: r.Project,
		Mode:    r.Policy,
		Proxies: v2Domains(r.ExternalProxyGlobs, cross),
	}
}

// v2Rules returns the allowed domains rule first, so that the engine checks the
// same globs in the same order as v1, and then one rule per MITM domain.
func v2Rules(id string, s aclv2.Subjects, r Rule, cross bool) []aclv2.Rule {
	var out []aclv2.Rule
	if len(r.DomainGlobs) > 0 {
		out = append(out, aclv2.Rule{
			ID:       id + "/allowed_domains",
			Action:   aclv2.ActionAllow,
			Subjects: s,
			Domains:  v2Domains(r.DomainGlobs, cross),
		})
	}
	for i, m := range r.MitmDomains {
		if !slices.Contains(r.DomainGlobs, m.Domain) {
			continue
		}
		out = append(out, aclv2.Rule{
			ID:       fmt.Sprintf("%s/mitm_domains/%d", id, i),
			Action:   aclv2.ActionAllow,
			Subjects: s,
			Domains:  v2Domains([]string{m.Domain}, cross),
			Mitm: &aclv2.MitmConfig{
				AddHeaders:                  m.AddHeaders,
				DetailedHttpLogs:            m.DetailedHttpLogs,
				DetailedHttpLogsFullHeaders: m.DetailedHttpLogsFullHeaders,
			},
		})
	}
	return out
}

func v2Domains(globs []string, cross bool) []aclv2.Domain {
	out := make([]aclv2.Domain, len(globs))
	for i, g := range globs {
		out[i] = aclv2.Domain{Glob: g, CrossPublicSuffix: cross}
	}
	return out
}
