package acl

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/stripe/smokescreen/v2/internal/logging"
	aclv2 "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
	"github.com/stripe/smokescreen/v2/pkg/smokescreen/hostport"
	"golang.org/x/net/publicsuffix"
)

// DecideArgs holds the arguments for an ACL decision. See the v2 package.
type DecideArgs = aclv2.DecideArgs

// Decider decides whether a request may reach its destination.
type Decider = aclv2.Decider

type ACL struct {
	Rules            map[string]Rule
	DefaultRule      *Rule
	GlobalDenyList   []string
	GlobalAllowList  []string
	DisabledPolicies []EnforcementPolicy
	// UnsafeAllowWildcardsAcrossPublicSuffixes lets label wildcards in allow
	// lists match hosts outside the glob's registrable domain, as they always
	// do in GlobalDenyList. See HostMatchesGlob.
	UnsafeAllowWildcardsAcrossPublicSuffixes bool
	logger                                   *slog.Logger
}

type Rule struct {
	Project            string
	Policy             EnforcementPolicy
	DomainGlobs        []string
	MitmDomains        []MitmDomain
	ExternalProxyGlobs []string
}

type MitmDomain struct {
	AddHeaders                  map[string]string
	DetailedHttpLogs            bool
	DetailedHttpLogsFullHeaders []string
	Domain                      string
}

// MitmConfig configures how a MITM request is handled.
type MitmConfig = aclv2.MitmConfig

// Decision is the result of an ACL check.
type Decision = aclv2.Decision

func New(logger *slog.Logger, loader Loader, disabledActions []string) (*ACL, error) {
	acl, err := loader.Load()
	if err != nil {
		return nil, err
	}

	err = acl.DisablePolicies(disabledActions)
	if err != nil {
		return nil, err
	}

	err = acl.Validate()
	if err != nil {
		return nil, err
	}

	acl.logger = logging.OrDefault(logger)

	if acl.DefaultRule == nil {
		acl.logger.Warn("no default rule set. any services without a rule will be denied.")
	}
	return acl, nil
}

// Add associates a rule with the specified service after verifying the rule's
// policy and domains are valid. Add returns an error if the service rule
// already exists.
func (acl *ACL) Add(svc string, r Rule) error {
	err := acl.PolicyDisabled(svc, r.Policy)
	if err != nil {
		return err
	}

	err = acl.ValidateRule(svc, r)
	if err != nil {
		return err
	}

	if _, ok := acl.Rules[svc]; ok {
		return fmt.Errorf("rule already exists for service %v", svc)
	}
	acl.Rules[svc] = r
	return nil
}

// Decide takes uses the rule configured for the given service to determine if
//  1. The CONNECT proxy host is in the rule's allowed domain
//  2. The host is in the rule's allowed domain
//  3. The host has been globally denied
//  4. The host has been globally allowed
//  5. There is a default rule for the ACL
func (acl *ACL) Decide(args DecideArgs) (Decision, error) {
	var d Decision

	rule := acl.Rule(args.Service)
	if rule == nil {
		d.Result = Deny
		d.Reason = "no rule matched"
		return d, nil
	}

	d.Project = rule.Project
	d.Default = rule == acl.DefaultRule

	if args.ConnectProxyHost != "" {
		shouldDeny := true
		for _, dg := range rule.ExternalProxyGlobs {
			if acl.hostMatchesAllowGlob(args.ConnectProxyHost, dg) {
				shouldDeny = false
				break
			}
		}

		// We can only break out early and return if we know that we should deny;
		// at this point the host hasn't been allowed by the rule, so we need to
		// continue to check it below (unless we know we should deny it already)
		if shouldDeny {
			d.Result = Deny
			d.Reason = "connect proxy host not allowed in rule" +
				acl.publicSuffixHint(args.ConnectProxyHost, rule.ExternalProxyGlobs)
			return d, nil
		}
	}

	// if the host matches any of the rule's allowed domains, allow
	for _, dg := range rule.DomainGlobs {
		if acl.hostMatchesAllowGlob(args.Host, dg) {
			d.Result, d.Reason = Allow, "host matched allowed domain in rule"
			// Check if we can find a matching MITM config
			for _, dg := range rule.MitmDomains {
				if acl.hostMatchesAllowGlob(args.Host, dg.Domain) {
					d.MitmConfig = &MitmConfig{
						AddHeaders:                  dg.AddHeaders,
						DetailedHttpLogs:            dg.DetailedHttpLogs,
						DetailedHttpLogsFullHeaders: dg.DetailedHttpLogsFullHeaders,
					}
					return d, nil
				}
			}
			return d, nil
		}
	}

	// if the host matches any of the global deny list, deny
	for _, dg := range acl.GlobalDenyList {
		if aclv2.MatchGlob(args.Host, dg, true) {
			d.Result, d.Reason = Deny, "host matched rule in global deny list"
			return d, nil
		}
	}

	// if the host matches any of the global allow list, allow
	for _, dg := range acl.GlobalAllowList {
		if acl.hostMatchesAllowGlob(args.Host, dg) {
			d.Result, d.Reason = Allow, "host matched rule in global allow list"
			return d, nil
		}
	}

	var err error
	switch rule.Policy {
	case Report:
		d.Result, d.Reason = AllowAndReport, "rule has allow and report policy"
	case Enforce:
		d.Result, d.Reason = Deny, "rule has enforce policy"
	case Open:
		d.Result, d.Reason = Allow, "rule has open enforcement policy"
	default:
		d.Result, d.Reason = Deny, "unexpected policy value"
		err = fmt.Errorf("unexpected policy value for (%s -> %s): %d", args.Service, args.Host, rule.Policy)
	}

	if d.Default {
		d.Reason = "default rule policy used"
	}

	if d.Result != Allow {
		d.Reason += acl.publicSuffixHint(args.Host, rule.DomainGlobs, acl.GlobalAllowList)
	}

	return d, err
}

// hostMatchesAllowGlob matches host against a glob from one of the ACL's allow
// lists, honoring UnsafeAllowWildcardsAcrossPublicSuffixes.
func (acl *ACL) hostMatchesAllowGlob(host string, glob string) bool {
	return aclv2.MatchGlob(host, glob, acl.UnsafeAllowWildcardsAcrossPublicSuffixes)
}

// publicSuffixHint explains why host was not allowed when a glob in one of
// globLists would have matched it but for the registrable domain check, so
// that operators can tell the public suffix list apart from a missing entry.
// It returns "" if no such glob exists. Callers must only use it once none of
// globLists matched host.
func (acl *ACL) publicSuffixHint(host string, globLists ...[]string) string {
	if acl.UnsafeAllowWildcardsAcrossPublicSuffixes {
		return ""
	}
	for _, globs := range globLists {
		for _, g := range globs {
			if !aclv2.MatchGlob(host, g, true) {
				continue
			}
			normalizedHost, err := hostport.NormalizeHost(host, false)
			if err != nil {
				return ""
			}
			suffix, _ := publicsuffix.PublicSuffix(strings.TrimRight(normalizedHost, "."))
			return fmt.Sprintf("; wildcard '%s' was not applied because '%s' is on the public suffix list", g, suffix)
		}
	}
	return ""
}

// DisablePolicies takes a slice of actions (open, report, enforce), maps them
// to their corresponding EnforcementPolicy, and adds them to the global
// disabledPolicy slice.
func (acl *ACL) DisablePolicies(actions []string) error {
	for _, a := range actions {
		p, err := PolicyFromAction(a)
		if err != nil {
			return err
		}
		acl.DisabledPolicies = append(acl.DisabledPolicies, p)
	}
	return nil
}

// Validate checks that the ACL has conformant domain globs in all rules,
// global lists, and external proxy configurations, and is not utilizing
// disabled enforcement policies.
func (acl *ACL) Validate() error {
	for svc, r := range acl.Rules {
		err := acl.ValidateRule(svc, r)
		if err != nil {
			return err
		}
		err = acl.PolicyDisabled(svc, r.Policy)
		if err != nil {
			return err
		}
	}
	if acl.DefaultRule != nil {
		err := acl.ValidateRule("default_rule", *acl.DefaultRule)
		if err != nil {
			return err
		}
		err = acl.PolicyDisabled("default_rule", acl.DefaultRule.Policy)
		if err != nil {
			return err
		}
	}

	// Validate global deny list
	for _, d := range acl.GlobalDenyList {
		err := ValidateDomainGlob("global_deny_list", d)
		if err != nil {
			return err
		}
	}

	// Validate global allow list
	for _, d := range acl.GlobalAllowList {
		err := ValidateDomainGlob("global_allow_list", d)
		if err != nil {
			return err
		}
	}

	return nil
}

func (acl *ACL) ValidateRule(svc string, r Rule) error {
	var err error
	for _, d := range r.DomainGlobs {
		err = ValidateDomainGlob(svc, d)
		if err != nil {
			return err
		}
	}
	for _, d := range r.MitmDomains {
		err = ValidateDomainGlob(svc, d.Domain)
		if err != nil {
			return err
		}
		// Check if the MITM config domain is also in DomainGlobs
		// Replace with slices.ContainsString when project upgraded to > 1.21
		if !containsString(r.DomainGlobs, d.Domain) {
			return fmt.Errorf("domain %s was added to mitm_domains but is missing in allowed_domains", d.Domain)
		}
	}
	// Validate external proxy globs
	for _, d := range r.ExternalProxyGlobs {
		err = ValidateDomainGlob(svc, d)
		if err != nil {
			return err
		}
	}
	return nil
}

func (*ACL) ValidateDomainGlob(svc string, glob string) error {
	return ValidateDomainGlob(svc, glob)
}

// ValidateDomainGlob verifies that glob follows smokescreen's domain glob
// policy. See the v2 package.
func ValidateDomainGlob(svc string, glob string) error {
	return aclv2.ValidateDomainGlob(svc, glob)
}

// PolicyDisabled checks if an EnforcementPolicy is disabled at the ACL level
func (acl *ACL) PolicyDisabled(svc string, p EnforcementPolicy) error {
	for _, dp := range acl.DisabledPolicies {
		if dp == p {
			return fmt.Errorf("rule for svc:%v utilizes a disabled policy:%v", svc, p)
		}
	}
	return nil
}

// Project returns the configured project for a service
func (acl *ACL) Project(service string) (string, error) {
	rule := acl.Rule(service)
	if rule == nil {
		return "", fmt.Errorf("no rule for service: %v", service)
	}
	return rule.Project, nil
}

// Rule returns the configured rule for a service, or the default rule if none
// is configured.
func (acl *ACL) Rule(service string) *Rule {
	if service, ok := acl.Rules[service]; ok {
		return &service
	}
	return acl.DefaultRule
}

// HostMatchesGlob matches a hostname string against a domain glob. See the
// v2 package.
func HostMatchesGlob(host string, domainGlob string) bool {
	return aclv2.HostMatchesGlob(host, domainGlob)
}

func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
