package acl

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/pkg/smokescreen/hostport"
	"golang.org/x/net/publicsuffix"
)

// DecideArgs holds the arguments for an ACL decision. Using a struct keeps the
// Decider interface stable as new fields are added (e.g. Req for request-aware
// authorization in custom Decider implementations). ACL.Decide does not
// inspect Req or ConnectReq; they are provided solely for use by custom implementations.
type DecideArgs struct {
	Req *http.Request
	// ConnectReq is the edge CONNECT request from the client when Decide is
	// evaluating a MITM inner HTTP request.
	ConnectReq       *http.Request
	Service          string
	Host             string
	ConnectProxyHost string
}

type Decider interface {
	Decide(args DecideArgs) (Decision, error)
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
			if HostMatchesGlob(args.ConnectProxyHost, dg) {
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
		if HostMatchesGlob(args.Host, dg) {
			d.Result, d.Reason = Allow, "host matched allowed domain in rule"
			// Check if we can find a matching MITM config
			for _, dg := range rule.MitmDomains {
				if HostMatchesGlob(args.Host, dg.Domain) {
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
		if hostMatchesGlob(args.Host, dg, false) {
			d.Result, d.Reason = Deny, "host matched rule in global deny list"
			return d, nil
		}
	}

	// if the host matches any of the global allow list, allow
	for _, dg := range acl.GlobalAllowList {
		if HostMatchesGlob(args.Host, dg) {
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

// ValidateDomainGlob takes a domain glob and verifies they conform to smokescreen's
// domain glob policy.
//
// Only a single wildcard per glob is allowed, in one of these forms:
//
//   - A leading "*." matches one or more subdomain labels (e.g., "*.example.com").
//   - A "*" spanning a label other than the leftmost one matches exactly one label
//     (e.g., "access-analyzer.*.amazonaws.com").
//   - A "*" after a literal prefix within a label matches one or more characters
//     within that label (e.g., "api*.example.com" or "web*-canary.example.com").
//
// Wildcards other than the leading "*." never cross a ".". The labels to the right
// of such a wildcard must be literal and form a registrable domain, so the wildcard
// can't reach into a public suffix such as "com", "co.uk", or "github.io". See
// HostMatchesGlob for how matches that cross into another registrable domain are
// handled.
//
// Globs must include text after a wildcard, and domains must use their normalized
// form (e.g., Punycode).
func ValidateDomainGlob(svc string, glob string) error {
	if glob == "" {
		return fmt.Errorf("glob cannot be empty")
	}

	if glob == "*" || glob == "*." {
		return fmt.Errorf("%v: %v: domain glob must not match everything", svc, glob)
	}

	if strings.Count(glob, "*") > 1 {
		return fmt.Errorf("%v: %v: only one wildcard is allowed per domain glob", svc, glob)
	}

	if !strings.HasPrefix(glob, "*.") && strings.Contains(glob, "*") {
		return validateLabelWildcardGlob(svc, glob)
	}

	// Extract domain part for validation (remove wildcard prefix if present)
	domainToCheck := strings.TrimPrefix(glob, "*.")

	normalizedDomain, err := hostport.NormalizeHost(domainToCheck, false)

	if err != nil {
		return fmt.Errorf("%v: %v: incorrect ACL entry: %v", svc, glob, err)
		// There was no error but the config contains a non-normalized form
	} else if normalizedDomain != domainToCheck {
		if strings.HasPrefix(glob, "*.") {
			// (Re-add) wildcard if one was provided (for the error message)
			normalizedDomain = "*." + normalizedDomain
		}
		return fmt.Errorf("%v: %v: incorrect ACL entry; use %q", svc, glob, normalizedDomain)
	}
	return nil
}

// validateLabelWildcardGlob validates a glob whose single wildcard sits inside a
// label (e.g., "api*.example.com"), as opposed to a leading "*." wildcard.
func validateLabelWildcardGlob(svc string, glob string) error {
	labels := strings.Split(strings.TrimSuffix(glob, "."), ".")
	idx := -1
	for i, l := range labels {
		if l == "" {
			return fmt.Errorf("%v: %v: domain glob must not contain empty labels", svc, glob)
		}
		if strings.Contains(l, "*") {
			idx = i
		}
	}

	label := labels[idx]
	// A leftmost whole-label wildcard is the leading "*." form, handled by the
	// caller. A leading "*" glued to a label is most likely a typo for "*." (e.g.,
	// "*bob.example.com" for "*.bob.example.com"), so require a literal prefix.
	if label != "*" && strings.HasPrefix(label, "*") {
		return fmt.Errorf("%v: %v: domain glob must represent a full prefix (sub)domain", svc, glob)
	}
	if strings.HasPrefix(label, "xn--") {
		return fmt.Errorf("%v: %v: wildcards are not supported in Punycode labels", svc, glob)
	}
	for _, r := range strings.Replace(label, "*", "", 1) {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return fmt.Errorf("%v: %v: wildcard label may only contain lowercase ASCII letters, digits, '-' and '_'", svc, glob)
		}
	}
	// The wildcard matches at least one character.
	if len(label) > 63 {
		return fmt.Errorf("%v: %v: wildcard label can never match a label of at most 63 characters", svc, glob)
	}

	if idx == len(labels)-1 {
		return fmt.Errorf("%v: %v: wildcard must not be in the top-level domain", svc, glob)
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return fmt.Errorf("%v: %v: domain glob must not match IP addresses", svc, glob)
	}

	// Validate the literal labels on either side of the wildcard label, preserving
	// the original form (e.g., a trailing dot) when checking normalization.
	rest := strings.SplitN(glob, ".", idx+2)[idx+1]
	parts := []string{rest}
	if idx > 0 {
		parts = append(parts, strings.Join(labels[:idx], "."))
	}
	for _, part := range parts {
		normalized, err := hostport.NormalizeHost(part, false)
		if err != nil {
			return fmt.Errorf("%v: %v: incorrect ACL entry: %v", svc, glob, err)
		}
		if normalized != part {
			return fmt.Errorf("%v: %v: incorrect ACL entry; %q must be in normalized form %q", svc, glob, part, normalized)
		}
	}

	// A wildcard directly under a public suffix would span registrable domains owned
	// by unrelated parties (e.g., "foo*.com" or "foo*.github.io").
	registrable, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(rest, "."))
	if err != nil {
		return fmt.Errorf("%v: %v: wildcard label must be followed by a registrable domain, not a public suffix", svc, glob)
	}
	// Reject globs whose wildcard sits under a wildcard public suffix rule (e.g.,
	// "*.compute.amazonaws.com"), since they could never match.
	example := strings.Join(labels, ".")
	example = strings.Replace(example, "*", "x", 1)
	if r, err := publicsuffix.EffectiveTLDPlusOne(example); err != nil || r != registrable {
		return fmt.Errorf("%v: %v: wildcard must not match a public suffix", svc, glob)
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
// converting both to a canonical form (punycode normalization, lowercase with trailing dots removed).
//
// For globs with a wildcard other than the leading "*.", the host must also have
// the same registrable domain as the glob's literal suffix, according to the public
// suffix list. This keeps "access-analyzer.*.amazonaws.com" from matching
// "access-analyzer.s3.amazonaws.com", which is an S3 bucket that anyone can own.
//
// domainGlob should already have been passed through ACL.Validate().
func HostMatchesGlob(host string, domainGlob string) bool {
	return hostMatchesGlob(host, domainGlob, true)
}

// hostMatchesGlob implements HostMatchesGlob. If sameRegistrableDomain is false,
// a label wildcard also matches hosts in another registrable domain, which is what
// deny lists need to stay as broad as they read.
func hostMatchesGlob(host string, domainGlob string, sameRegistrableDomain bool) bool {
	if host == "" {
		return false
	}

	// Normalize both the request host and the glob to ASCII/Punycode.
	// Handle optional wildcard prefix by normalizing only the domain part.
	normalizedHost, err := hostport.NormalizeHost(host, false)
	if err != nil {
		return false
	}

	if !strings.HasPrefix(domainGlob, "*.") && strings.Contains(domainGlob, "*") {
		h := strings.TrimRight(normalizedHost, ".")
		g := strings.TrimRight(strings.ToLower(domainGlob), ".")
		return hostMatchesLabelWildcard(h, g, sameRegistrableDomain)
	}

	hasWildcard := strings.HasPrefix(domainGlob, "*.")
	domainPart := domainGlob
	if hasWildcard {
		domainPart = strings.TrimPrefix(domainGlob, "*.")
	}

	normalizedGlob, err := hostport.NormalizeHost(domainPart, false)
	if err != nil {
		return false
	}

	h := strings.TrimRight(strings.ToLower(normalizedHost), ".")
	g := strings.TrimRight(strings.ToLower(normalizedGlob), ".")

	if hasWildcard {
		// Wildcard matches any subdomain of g (e.g., *.example.com), not the root itself
		suffix := "." + g
		if strings.HasSuffix(h, suffix) {
			return true
		}
	} else if g == h {
		return true
	}
	return false
}

// hostMatchesLabelWildcard reports whether the normalized host h matches g, a glob
// with a single wildcard confined to one label. A whole-label wildcard matches any
// one label, and a wildcard after a literal prefix matches one or more characters.
// h must have exactly as many labels as g, and every other label must match
// exactly.
func hostMatchesLabelWildcard(h, g string, sameRegistrableDomain bool) bool {
	hostLabels := strings.Split(h, ".")
	globLabels := strings.Split(g, ".")
	if len(hostLabels) != len(globLabels) {
		return false
	}
	idx := -1
	for i, gl := range globLabels {
		hl := hostLabels[i]
		prefix, suffix, ok := strings.Cut(gl, "*")
		if !ok {
			if hl != gl {
				return false
			}
			continue
		}
		// Fail closed on shapes that ValidateDomainGlob rejects.
		if idx != -1 || strings.Contains(suffix, "*") || (prefix == "" && (suffix != "" || i == 0)) {
			return false
		}
		idx = i
		if len(hl) <= len(prefix)+len(suffix) || !strings.HasPrefix(hl, prefix) || !strings.HasSuffix(hl, suffix) {
			return false
		}
	}
	if idx == -1 || idx == len(globLabels)-1 {
		return false
	}
	if !sameRegistrableDomain {
		return true
	}
	want, err := publicsuffix.EffectiveTLDPlusOne(strings.Join(globLabels[idx+1:], "."))
	if err != nil {
		return false
	}
	got, err := publicsuffix.EffectiveTLDPlusOne(h)
	return err == nil && got == want
}

func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
