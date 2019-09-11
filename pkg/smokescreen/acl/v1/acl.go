package acl

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

type ACL struct {
	rules            map[string]Rule
	defaultRule      *Rule
	globalDenyList   []string
	globalAllowList  []string
	disabledPolicies []EnforcementPolicy
	*logrus.Logger
}

type Rule struct {
	project     string
	policy      EnforcementPolicy
	domainGlobs []string
}

type Decision struct {
	Reason  string
	Default bool
	Result  DecisionResult
}

func New(logger *logrus.Logger, loader Loader, disabledActions []string) (*ACL, error) {
	acl, err := loader.Load()
	if err != nil {
		return nil, err
	}

	acl.DisablePolicies(disabledActions)

	err = acl.Validate()
	if err != nil {
		return nil, err
	}

	acl.Logger = logger

	if acl.defaultRule == nil {
		acl.Warn("no default rule set")
	}
	return acl, nil
}

// Add associates a rule with the specified service after verifying the rule's
// policy and domains are valid.
func (acl *ACL) Add(svc string, r Rule) error {
	err := acl.PolicyDisabled(svc, r.policy)
	if err != nil {
		return err
	}

	err = acl.ValidateDomains(r.domainGlobs)
	if err != nil {
		return err
	}

	acl.rules[svc] = r
	return nil
}

// Decide takes uses the rule configured for the given service to determine if
//   1. The host is in the rule's allowed domain
//   2. The host has been globally denied
//   3. The host has been globally allowed
//   4. There is a default rule for the ACL
func (acl *ACL) Decide(service, host string) (Decision, error) {
	var d Decision

	rule := acl.Rule(service)
	if rule == nil {
		d.Result = Deny
		d.Reason = "no rule matched"
		return d, nil
	}

	d.Default = rule == acl.defaultRule

	// if the host matches any of the rule's allowed domains, allow
	for _, dg := range rule.domainGlobs {
		if hostMatchesGlob(host, dg) {
			d.Result, d.Reason = Allow, "host matched allowed domain in rule"
			return d, nil
		}
	}

	// if the host matches any of the global deny list, deny
	for _, dg := range acl.globalDenyList {
		if hostMatchesGlob(host, dg) {
			d.Result, d.Reason = Deny, "host matched rule in global deny list"
			return d, nil
		}
	}

	// if the host matches any of the global allow list, allow
	for _, dg := range acl.globalAllowList {
		if hostMatchesGlob(host, dg) {
			d.Result, d.Reason = Allow, "host matched rule in global allow list"
			return d, nil
		}
	}

	var err error
	switch rule.policy {
	case Report:
		d.Result, d.Reason = AllowAndReport, "rule has allow and report policy"
	case Enforce:
		d.Result, d.Reason = Deny, "rule has enforce policy"
	case Open:
		d.Result, d.Reason = Allow, "rule has open enforcement policy"
	default:
		d.Result, d.Reason = Unknown, "unexpected policy value"
		err = fmt.Errorf("unexpected policy value for (%s -> %s): %d", service, host, rule.policy)
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
		acl.disabledPolicies = append(acl.disabledPolicies, p)
	}
	return nil
}

// Validate checks that the ACL that every rule has a conformant domain glob
// and is not utilizing a disabled enforcement policy.
func (acl *ACL) Validate() error {
	for svc, r := range acl.rules {
		err := acl.ValidateDomains(r.domainGlobs)
		if err != nil {
			return err
		}
		err = acl.PolicyDisabled(svc, r.policy)
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidateDomains takes a slice of domains and verifies they conform to
// smokescreen's domain glob policy.
//
// Domains can only contain a single wildcard prefix
// Domains cannot be represented as a sole wildcard
func (acl *ACL) ValidateDomains(domains []string) error {
	for _, d := range domains {
		if d == "" {
			return fmt.Errorf("glob cannot be empty")
		}

		if !strings.HasPrefix(d, "*.") && strings.HasPrefix(d, "*") {
			return fmt.Errorf("glob must represent a full prefix (sub)domain")
		}

		domainToCheck := d
		if strings.HasPrefix(domainToCheck, "*") {
			domainToCheck = domainToCheck[1:]
		}
		if strings.Contains(domainToCheck, "*") {
			return fmt.Errorf("globs are only supported as prefix")
		}
	}
	return nil
}

// PolicyDisabled checks if an EnforcementPolicy is disabled at the ACL level
func (acl *ACL) PolicyDisabled(svc string, p EnforcementPolicy) error {
	for _, dp := range acl.disabledPolicies {
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
	return rule.project, nil
}

// Rule returns the configured rule for a service, or the default rule if none
// is configured.
func (acl *ACL) Rule(service string) *Rule {
	if service, ok := acl.rules[service]; ok {
		return &service
	}
	return acl.defaultRule
}

func hostMatchesGlob(host string, domainGlob string) bool {
	if domainGlob != "" && domainGlob[0] == '*' {
		suffix := domainGlob[1:]
		if strings.HasSuffix(host, suffix) {
			return true
		}
	} else if domainGlob == host {
		return true
	}
	return false
}
