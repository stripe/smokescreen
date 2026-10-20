package acl

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"
)

// Version is the value of the version key in a v2 ACL file.
const Version = "v2"

// Policy is a v2 ACL. Roles say who exists and what happens when no rule
// matches. Rules say which destinations a subject may or may not reach.
type Policy struct {
	Version string `yaml:"version"`
	Roles   []Role `yaml:"roles"`
	// UnknownRole applies to requests from roles that are not in Roles. If it is
	// nil, those requests are denied.
	UnknownRole *Role  `yaml:"unknown_role"`
	Rules       []Rule `yaml:"rules"`
}

// Role is a service identity. For UnknownRole, Name is empty.
type Role struct {
	Name    string `yaml:"name"`
	Project string `yaml:"project"`
	// Mode decides requests that no rule matches.
	Mode Mode `yaml:"mode"`
	// Proxies are the upstream proxies that the role may CONNECT through.
	Proxies []Domain `yaml:"proxies"`
}

// Action is what a rule does to a matching request.
type Action string

// Possible actions.
const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Rule allows or denies its domains for its subjects.
type Rule struct {
	ID       string   `yaml:"id"`
	Action   Action   `yaml:"action"`
	Subjects Subjects `yaml:"subjects"`
	Domains  []Domain `yaml:"domains"`
	// Mitm applies to requests that this rule allows. Only role-scoped allow
	// rules can have it.
	Mitm *MitmConfig `yaml:"mitm"`
	// Overrides names the any-scoped deny rules that this role-scoped allow rule
	// wins over. Validation requires an entry for each deny rule it overlaps.
	Overrides []string `yaml:"overrides"`
}

// Subjects is who a rule applies to. Set exactly one field.
type Subjects struct {
	Roles       []string `yaml:"roles"`
	UnknownRole bool     `yaml:"unknown_role"`
	Any         bool     `yaml:"any"`
}

// Scope orders subjects from most to least specific.
type Scope int

// Possible scopes. A role-scoped rule applies to named roles or to the
// unknown role.
const (
	ScopeRole Scope = iota
	ScopeAny
)

// Scope returns the scope of the subjects.
func (s Subjects) Scope() Scope {
	if s.Any {
		return ScopeAny
	}
	return ScopeRole
}

// Domain is a domain glob. In a file it is either a string or a mapping with
// glob and cross_public_suffix keys.
type Domain struct {
	Glob string `yaml:"glob"`
	// CrossPublicSuffix lets a label wildcard match hosts outside the glob's
	// registrable domain. See MatchGlob.
	CrossPublicSuffix bool `yaml:"cross_public_suffix"`
}

// UnmarshalYAML accepts a plain string as a Domain with only a glob.
func (d *Domain) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&d.Glob)
	}
	type plain Domain
	return n.Decode((*plain)(d))
}

// UnmarshalYAML reads a mode name.
func (m *Mode) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	mode, err := ModeFromString(s)
	if err != nil {
		return err
	}
	*m = mode
	return nil
}

// MarshalYAML writes a mode name.
func (m Mode) MarshalYAML() (interface{}, error) {
	for name, mode := range Modes {
		if mode == m {
			return name, nil
		}
	}
	return nil, fmt.Errorf("unknown mode %d", m)
}

// Parse decodes a v2 ACL file. Unknown keys are an error.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if p.Version != Version {
		return nil, fmt.Errorf("expected version %q got %q", Version, p.Version)
	}
	return &p, nil
}

// FileVersion returns the version key of an ACL file of any version.
func FileVersion(data []byte) (string, error) {
	var v struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &v); err != nil {
		return "", err
	}
	return v.Version, nil
}

// Options change how Compile validates a policy.
type Options struct {
	// DisabledModes are modes that no role may use.
	DisabledModes []Mode
}

// Validate checks that the policy is complete and that every rule is
// reachable and unambiguous.
func (p *Policy) Validate(opts Options) error {
	roles := make(map[string]bool, len(p.Roles))
	for _, r := range p.Roles {
		if r.Name == "" {
			return errors.New("role with empty name")
		}
		if roles[r.Name] {
			return fmt.Errorf("role %q is defined more than once", r.Name)
		}
		roles[r.Name] = true
		if err := validateRole(r.Name, r, opts); err != nil {
			return err
		}
	}
	if p.UnknownRole != nil {
		if err := validateRole("unknown_role", *p.UnknownRole, opts); err != nil {
			return err
		}
	}

	denies := map[string]Rule{}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		if r.ID == "" {
			return errors.New("rule with empty id")
		}
		if ids[r.ID] {
			return fmt.Errorf("rule id %q is used more than once", r.ID)
		}
		ids[r.ID] = true
		if r.Action == ActionDeny && r.Subjects.Scope() == ScopeAny {
			denies[r.ID] = r
		}
	}

	for _, r := range p.Rules {
		if err := p.validateRule(r, roles, denies); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

func validateRole(name string, r Role, opts Options) error {
	if r.Mode == ModeUnknown {
		return fmt.Errorf("role %q: mode is required", name)
	}
	for _, m := range opts.DisabledModes {
		if r.Mode == m {
			return fmt.Errorf("rule for svc:%v utilizes a disabled policy:%v", name, m)
		}
	}
	for _, d := range r.Proxies {
		if err := ValidateDomainGlob(name, d.Glob); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) validateRule(r Rule, roles map[string]bool, denies map[string]Rule) error {
	if r.Action != ActionAllow && r.Action != ActionDeny {
		return fmt.Errorf("action must be %q or %q", ActionAllow, ActionDeny)
	}
	set := 0
	if len(r.Subjects.Roles) > 0 {
		set++
	}
	if r.Subjects.UnknownRole {
		set++
	}
	if r.Subjects.Any {
		set++
	}
	if set != 1 {
		return errors.New("subjects must set exactly one of roles, unknown_role or any")
	}
	for _, name := range r.Subjects.Roles {
		if !roles[name] {
			return fmt.Errorf("subject role %q is not defined", name)
		}
	}
	if r.Subjects.UnknownRole && p.UnknownRole == nil {
		return errors.New("subject unknown_role is not defined")
	}
	if len(r.Domains) == 0 {
		return errors.New("domains must not be empty")
	}
	for _, d := range r.Domains {
		if err := ValidateDomainGlob(r.ID, d.Glob); err != nil {
			return err
		}
	}
	if r.Mitm != nil && (r.Action != ActionAllow || r.Subjects.Scope() != ScopeRole) {
		return errors.New("mitm is only allowed on role-scoped allow rules")
	}

	if r.Action != ActionAllow || r.Subjects.Scope() != ScopeRole {
		if len(r.Overrides) > 0 {
			return errors.New("overrides is only allowed on role-scoped allow rules")
		}
		return nil
	}
	listed := map[string]bool{}
	for _, id := range r.Overrides {
		if _, ok := denies[id]; !ok {
			return fmt.Errorf("overrides %q, which is not an any-scoped deny rule", id)
		}
		listed[id] = true
	}
	for id, deny := range denies {
		if !listed[id] && rulesOverlap(r, deny) {
			return fmt.Errorf("overlaps deny rule %q; add it to overrides", id)
		}
	}
	return nil
}

func rulesOverlap(a, b Rule) bool {
	for _, x := range a.Domains {
		for _, y := range b.Domains {
			if globsOverlap(x.Glob, y.Glob) {
				return true
			}
		}
	}
	return false
}

// AddOverrides adds every any-scoped deny rule that a role-scoped allow rule
// overlaps to that rule's Overrides. Translators from other formats use it to
// write down overrides that those formats leave implicit.
func (p *Policy) AddOverrides() {
	var denies []Rule
	for _, r := range p.Rules {
		if r.Action == ActionDeny && r.Subjects.Scope() == ScopeAny {
			denies = append(denies, r)
		}
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action != ActionAllow || r.Subjects.Scope() != ScopeRole {
			continue
		}
		for _, d := range denies {
			if rulesOverlap(*r, d) && !slices.Contains(r.Overrides, d.ID) {
				r.Overrides = append(r.Overrides, d.ID)
			}
		}
	}
}
