package acl

import (
	"errors"
	"fmt"
	"slices"
)

// Options change how a policy is parsed and validated.
type Options struct {
	// AllowUnknownFields makes parsing ignore keys that the v2 format does
	// not define, as v1 did, so that a file can also carry keys that other
	// tools read. By default an unknown key is an error, so that a misspelled
	// key fails to load instead of silently doing nothing. A caller that sets
	// this must validate its own keys, and loses that protection for typos.
	AllowUnknownFields bool
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
	if err := validateGlobs(name, s.Proxies); err != nil {
		return err
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

func validateDomains(where string, domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("%s: domains must not be empty", where)
	}
	return validateGlobs(where, domains)
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
			if globsOverlap(globPattern{x, e.CrossPublicSuffix}, denyPattern(g)) {
				return g, true
			}
		}
	}
	return "", false
}

// denyPattern returns the pattern that a deny glob matches as: deny globs
// always match across public suffixes.
func denyPattern(glob string) globPattern {
	return globPattern{glob, true}
}
