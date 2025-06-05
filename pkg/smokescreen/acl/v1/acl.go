package acl

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/pkg/smokescreen/hostport"
)

type Decider interface {
	Decide(service, host, connectProxyHost string) (Decision, error)
}

type ACL struct {
	Rules            map[string]Rule
	DefaultRule      *Rule
	GlobalDenyList   []string
	GlobalAllowList  []string
	DisabledPolicies []EnforcementPolicy
	*logrus.Logger
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

type MitmConfig struct {
	AddHeaders                  map[string]string
	DetailedHttpLogs            bool
	DetailedHttpLogsFullHeaders []string
}

type Decision struct {
	Reason     string
	Default    bool
	Result     DecisionResult
	Project    string
	MitmConfig *MitmConfig
}

func New(logger *logrus.Logger, loader Loader, disabledActions []string) (*ACL, error) {
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

	acl.Logger = logger

	if acl.DefaultRule == nil {
		acl.Warn("no default rule set. any services without a rule will be denied.")
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
func (acl *ACL) Decide(service, host, connectProxyHost string) (Decision, error) {
	var d Decision

	rule := acl.Rule(service)
	if rule == nil {
		d.Result = Deny
		d.Reason = "no rule matched"
		return d, nil
	}

	d.Project = rule.Project
	d.Default = rule == acl.DefaultRule

	if connectProxyHost != "" {
		shouldDeny := true
		for _, dg := range rule.ExternalProxyGlobs {
			if HostMatchesGlob(connectProxyHost, dg) {
				shouldDeny = false
				break
			}
		}

		// We can only break out early and return if we know that we should deny;
		// at this point the host hasn't been allowed by the rule, so we need to
		// continue to check it below (unless we know we should deny it already)
		if shouldDeny {
			d.Result = Deny
			d.Reason = "connect proxy host not allowed in rule"
			return d, nil
		}
	}

	// if the host matches any of the rule's allowed domains, allow
	for _, dg := range rule.DomainGlobs {
		if HostMatchesGlob(host, dg) {
			d.Result, d.Reason = Allow, "host matched allowed domain in rule"
			// Check if we can find a matching MITM config
			for _, dg := range rule.MitmDomains {
				if HostMatchesGlob(host, dg.Domain) {
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
		if HostMatchesGlob(host, dg) {
			d.Result, d.Reason = Deny, "host matched rule in global deny list"
			return d, nil
		}
	}

	// if the host matches any of the global allow list, allow
	for _, dg := range acl.GlobalAllowList {
		if HostMatchesGlob(host, dg) {
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
		err = fmt.Errorf("unexpected policy value for (%s -> %s): %d", service, host, rule.Policy)
	}

	if d.Default {
		d.Reason = "default rule policy used"
	}

	return d, err
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

// Validate checks that the ACL that every rule has a conformant domain glob
// and is not utilizing a disabled enforcement policy.
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

	return nil
}

func (acl *ACL) ValidateRule(svc string, r Rule) error {
	var err error
	for _, d := range r.DomainGlobs {
		err = acl.ValidateDomainGlob(svc, d)
		if err != nil {
			return err
		}
	}
	for _, d := range r.MitmDomains {
		err = acl.ValidateDomainGlob(svc, d.Domain)
		if err != nil {
			return err
		}
		// Check if the MITM config domain is also in DomainGlobs
		// Replace with slices.ContainsString when project upgraded to > 1.21
		if !containsString(r.DomainGlobs, d.Domain) {
			return fmt.Errorf("domain %s was added to mitm_domains but is missing in allowed_domains", d.Domain)
		}
	}
	return nil
}

// ValidateDomainGlob takes a domain glob and verifies they conform to smokescreen's
// domain glob policy.
//
// Wildcards are valid at any position in a domain glob, but must represent complete
// domain components (e.g., "*.example.com", "service.*.amazonaws.com"). Multiple
// Globs must include text after a wildcard.
// Domains must use their normalized form (e.g., Punycode)
func (*ACL) ValidateDomainGlob(svc string, glob string) error {
	if glob == "" {
		return fmt.Errorf("glob cannot be empty")
	}

	if glob == "*" || glob == "*." || glob == "*.*" {
		return fmt.Errorf("%v: %v: domain glob must not match everything", svc, glob)
	}

	// Split the glob into components and validate each one
	components := strings.Split(glob, ".")
	wildcardCount := 0
	nonWildcardCount := 0

	for i, component := range components {
		if component == "*" {
			wildcardCount++
			continue
		} else {
			nonWildcardCount++
		}

		if strings.Contains(component, "*") {
			// Partial wildcards within a component are not allowed
			return fmt.Errorf("%v: %v: wildcards must represent complete domain components", svc, glob)
		}

		// For non-wildcard components, validate they are proper domain parts
		if component == "" && i != len(components)-1 {
			// Empty components are only allowed at the end (trailing dot)
			return fmt.Errorf("%v: %v: invalid domain format", svc, glob)
		}
	}

	// Check if all components are wildcards first
	if nonWildcardCount == 0 {
		return fmt.Errorf("%v: %v: domain glob must contain at least one non-wildcard component", svc, glob)
	}

	// Check if the last component (TLD) is a wildcard - this would be dangerous for any pattern
	if len(components) > 0 && components[len(components)-1] == "*" {
		return fmt.Errorf("%v: %v: wildcard TLD patterns are not allowed", svc, glob)
	}

	// Check if multiple wildcards are allowed
	if wildcardCount > 1 {
		// Multiple wildcards are allowed as long as we don't have a pattern that could match any TLD
		// We need at least one non-wildcard component before the TLD to prevent overly broad matches

		// For patterns like *.*.com, we need to ensure there's at least one specific domain component
		// Count non-wildcard components excluding the TLD
		nonWildcardExcludingTLD := 0
		for i := 0; i < len(components)-1; i++ {
			if components[i] != "*" {
				nonWildcardExcludingTLD++
			}
		}

		// We need at least one non-wildcard component before the TLD
		if nonWildcardExcludingTLD == 0 {
			return fmt.Errorf("%v: %v: multiple wildcards require at least one non-wildcard component before the TLD", svc, glob)
		}
	}

	// Reconstruct the domain without wildcards for normalization check
	// We'll check the longest non-wildcard suffix for normalization
	var domainToCheck string
	for i := len(components) - 1; i >= 0; i-- {
		if components[i] != "*" && components[i] != "" {
			if domainToCheck == "" {
				domainToCheck = components[i]
			} else {
				domainToCheck = components[i] + "." + domainToCheck
			}
		} else if components[i] == "*" {
			// Stop at the first wildcard when building suffix
			break
		}
	}

	// If we have a domain suffix to check, validate it's normalized
	if domainToCheck != "" {
		normalizedDomain, err := hostport.NormalizeHost(domainToCheck, false)
		if err != nil {
			return fmt.Errorf("%v: %v: incorrect ACL entry: %v", svc, glob, err)
		}
		if normalizedDomain != domainToCheck {
			return fmt.Errorf("%v: %v: incorrect ACL entry; domain components must be normalized", svc, glob)
		}
	}

	return nil
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

// HostMatchesGlob matches a hostname string against a domain glob after
// converting both to a canonical form (lowercase with trailing dots removed).
//
// domainGlob should already have been passed through ACL.Validate().
func HostMatchesGlob(host string, domainGlob string) bool {
	if host == "" {
		return false
	}

	h := strings.TrimRight(strings.ToLower(host), ".")
	g := strings.TrimRight(strings.ToLower(domainGlob), ".")

	// If no wildcards, do exact match
	if !strings.Contains(g, "*") {
		return g == h
	}

	// Split both host and glob into components
	hostComponents := strings.Split(h, ".")
	globComponents := strings.Split(g, ".")

	return matchComponents(hostComponents, globComponents)
}

// matchComponents recursively matches host components against glob components
func matchComponents(hostComponents, globComponents []string) bool {
	// If we've consumed all glob components, we should have consumed all host components too
	if len(globComponents) == 0 {
		return len(hostComponents) == 0
	}

	// If we've consumed all host components but still have non-wildcard glob components, no match
	if len(hostComponents) == 0 {
		// Check if remaining glob components are all wildcards (shouldn't happen with validation, but defensive)
		for _, gc := range globComponents {
			if gc != "*" {
				return false
			}
		}
		return true
	}

	currentGlob := globComponents[0]

	if currentGlob == "*" {
		// For leading wildcards (*.suffix), maintain backward compatibility by allowing multiple component matches
		if len(globComponents) > 1 && len(hostComponents) > 0 {
			// Check if this is a leading wildcard pattern
			isLeadingWildcard := true
			for i := 1; i < len(globComponents); i++ {
				if globComponents[i] == "*" {
					isLeadingWildcard = false
					break
				}
			}

			if isLeadingWildcard {
				// Leading wildcard: try to find a match for the suffix in the remaining host components
				suffix := globComponents[1:]
				for i := 1; i <= len(hostComponents); i++ {
					if matchComponents(hostComponents[i:], suffix) {
						return true
					}
				}
				return false
			}
		}

		// For non-leading wildcards or multiple wildcard patterns, match exactly one component
		return matchComponents(hostComponents[1:], globComponents[1:])
	} else {
		// Exact component match required
		if hostComponents[0] != currentGlob {
			return false
		}
		return matchComponents(hostComponents[1:], globComponents[1:])
	}
}

func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
