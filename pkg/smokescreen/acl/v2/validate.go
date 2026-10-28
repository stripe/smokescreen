package acl

import (
	"errors"
	"fmt"
	"slices"
)

// Options change how a policy is validated.
type Options struct {
	// DisabledModes are actions that no service may use.
	DisabledModes []Mode
	// Compat keeps the v1 behavior for a service allow entry that overlaps
	// the global deny list without setting OverrideGlobalPolicy: the entry
	// still wins over the global deny list, and validation reports it to Warn
	// instead of failing. This gives existing ACLs time to add the field.
	Compat bool
	// Warn receives the warnings that validation reports in compat mode. If
	// it is nil, the warnings are dropped.
	Warn func(msg string)
}

// Validate checks that the policy is complete and that every entry is
// reachable and unambiguous.
func (p *Policy) Validate(opts Options) error {
	if err := validateGlobs("global.deny", p.Global.Deny); err != nil {
		return err
	}
	for i, e := range p.Global.Allow {
		where := fmt.Sprintf("global.allow[%d]", i)
		if e.Mitm != nil || e.OverrideGlobalPolicy {
			return fmt.Errorf("%s: mitm and override_global_policy are only allowed on service allow entries", where)
		}
		if err := validateDomains(where, e.Domains); err != nil {
			return err
		}
	}

	names := make(map[string]bool, len(p.Services))
	for _, s := range p.Services {
		if s.Name == "" {
			return errors.New("service with empty name")
		}
		if names[s.Name] {
			return fmt.Errorf("service %q is defined more than once", s.Name)
		}
		names[s.Name] = true
		if err := validateService(s.Name, s, p.Global.Deny, opts); err != nil {
			return err
		}
	}
	if p.Default != nil {
		if p.Default.Name != "" {
			return errors.New("default: name is not allowed")
		}
		if err := validateService("default", *p.Default, p.Global.Deny, opts); err != nil {
			return err
		}
	}
	return nil
}

func validateService(name string, s Service, globalDeny []string, opts Options) error {
	if s.Action == ModeUnknown {
		return fmt.Errorf("%s: action is required", name)
	}
	if slices.Contains(opts.DisabledModes, s.Action) {
		return fmt.Errorf("rule for svc:%v utilizes a disabled policy:%v", name, s.Action)
	}
	for _, d := range s.Proxies {
		if err := ValidateDomainGlob(name, d.Glob); err != nil {
			return err
		}
	}
	if err := validateGlobs(name+": deny", s.Deny); err != nil {
		return err
	}
	for i, e := range s.Allow {
		where := fmt.Sprintf("%s: allow[%d]", name, i)
		if err := validateDomains(where, e.Domains); err != nil {
			return err
		}
		if e.OverrideGlobalPolicy {
			continue
		}
		deny, ok := overlappingDeny(e, globalDeny)
		if !ok {
			continue
		}
		if !opts.Compat {
			return fmt.Errorf("%s: overlaps global deny %q; set override_global_policy: true to allow it", where, deny)
		}
		if opts.Warn != nil {
			opts.Warn(fmt.Sprintf("%s: overlaps global deny %q without override_global_policy; allowed in compat mode", where, deny))
		}
	}
	return nil
}

func validateDomains(where string, domains []Domain) error {
	if len(domains) == 0 {
		return fmt.Errorf("%s: domains must not be empty", where)
	}
	for _, d := range domains {
		if err := ValidateDomainGlob(where, d.Glob); err != nil {
			return err
		}
	}
	return nil
}

func validateGlobs(where string, globs []string) error {
	for _, g := range globs {
		if err := ValidateDomainGlob(where, g); err != nil {
			return err
		}
	}
	return nil
}

// overlappingDeny returns the first global deny glob that some host could
// match together with one of e's domains.
func overlappingDeny(e Entry, globalDeny []string) (string, bool) {
	for _, x := range e.Domains {
		for _, g := range globalDeny {
			if globsOverlap(x, denyDomain(g)) {
				return g, true
			}
		}
	}
	return "", false
}

// denyDomain returns the Domain that a deny glob matches as: deny globs always
// match across public suffixes.
func denyDomain(glob string) Domain {
	return Domain{Glob: glob, CrossPublicSuffix: true}
}
