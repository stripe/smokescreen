package acl

import (
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/stripe/smokescreen/v2/internal/logging"
	aclv2 "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
)

// DecideArgs holds the arguments for an ACL decision. See the v2 package.
type DecideArgs = aclv2.DecideArgs

// Decider decides whether a request may reach its destination.
type Decider = aclv2.Decider

// ACL is a v1 egress ACL. Decisions use the v2 engine, compiled from the ACL
// by Validate or by the first Decide. Do not change the fields after the first
// decision; call Validate to apply a change.
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
	// engine is the compiled v2 engine. Add clears it.
	engine atomic.Pointer[aclv2.Engine]
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
	acl.engine.Store(nil)
	return nil
}

// Decide translates the ACL into a v2 policy and decides with the v2 engine.
// See ToV2 and the v2 Engine.Decide for the order of checks. The first call
// on an ACL that Validate has not compiled builds the engine and keeps it.
func (acl *ACL) Decide(args DecideArgs) (Decision, error) {
	e := acl.engine.Load()
	if e == nil {
		e = aclv2.NewEngine(acl.ToV2())
		acl.engine.CompareAndSwap(nil, e)
	}
	return e.Decide(args)
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

	acl.engine.Store(aclv2.NewEngine(acl.ToV2()))
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
