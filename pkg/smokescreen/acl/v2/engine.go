package acl

import (
	"fmt"
	"os"
)

// Engine decides requests with a compiled Policy. It is safe for concurrent use
// and does not change after it is built.
type Engine struct {
	roles   map[string]*compiledRole
	unknown *compiledRole
	anyDeny []Rule
	anyAll  []Rule
}

type compiledRole struct {
	role  Role
	deny  []Rule
	allow []Rule
}

// Compile validates p and builds an Engine from it.
func Compile(p *Policy, opts Options) (*Engine, error) {
	if err := p.Validate(opts); err != nil {
		return nil, err
	}
	return NewEngine(p), nil
}

// NewEngine builds an Engine from p without validating it. Use Compile for
// policies that come from files.
func NewEngine(p *Policy) *Engine {
	e := &Engine{roles: make(map[string]*compiledRole, len(p.Roles))}
	for _, r := range p.Roles {
		e.roles[r.Name] = &compiledRole{role: r}
	}
	if p.UnknownRole != nil {
		e.unknown = &compiledRole{role: *p.UnknownRole}
	}
	for _, r := range p.Rules {
		switch {
		case r.Subjects.Any:
			if r.Action == ActionDeny {
				e.anyDeny = append(e.anyDeny, r)
			} else {
				e.anyAll = append(e.anyAll, r)
			}
		case r.Subjects.UnknownRole:
			e.unknown.add(r)
		default:
			for _, name := range r.Subjects.Roles {
				e.roles[name].add(r)
			}
		}
	}
	return e
}

func (c *compiledRole) add(r Rule) {
	if c == nil {
		return
	}
	if r.Action == ActionDeny {
		c.deny = append(c.deny, r)
	} else {
		c.allow = append(c.allow, r)
	}
}

// Decide applies the policy to one request:
//  1. Requests from roles that are not defined use the unknown role, or are
//     denied if there is none.
//  2. A CONNECT proxy host must match one of the role's proxies.
//  3. Role-scoped rules decide if one matches. Deny rules win over allow rules.
//  4. Otherwise any-scoped rules decide if one matches, with deny rules first.
//  5. Otherwise the role's mode decides.
func (e *Engine) Decide(args DecideArgs) (Decision, error) {
	var d Decision

	role, ok := e.roles[args.Service]
	if !ok {
		role = e.unknown
		d.Default = true
	}
	if role == nil {
		return Decision{Result: Deny, Reason: "no rule matched"}, nil
	}
	d.Project = role.role.Project

	if args.ConnectProxyHost != "" && !matchesAny(args.ConnectProxyHost, role.role.Proxies) {
		d.Result = Deny
		d.Reason = "connect proxy host not allowed in rule" +
			publicSuffixHint(args.ConnectProxyHost, role.role.Proxies)
		return d, nil
	}

	for _, r := range role.deny {
		if matchesAny(args.Host, r.Domains) {
			d.Result, d.Reason = Deny, "host matched denied domain in rule"
			return d, nil
		}
	}
	for _, r := range role.allow {
		if matchesAny(args.Host, r.Domains) {
			d.Result, d.Reason = Allow, "host matched allowed domain in rule"
			d.MitmConfig = role.mitm(args.Host)
			return d, nil
		}
	}

	for _, r := range e.anyDeny {
		if matchesAny(args.Host, r.Domains) {
			d.Result, d.Reason = Deny, "host matched rule in global deny list"
			return d, nil
		}
	}
	for _, r := range e.anyAll {
		if matchesAny(args.Host, r.Domains) {
			d.Result, d.Reason = Allow, "host matched rule in global allow list"
			return d, nil
		}
	}

	var err error
	switch role.role.Mode {
	case ModeReport:
		d.Result, d.Reason = AllowAndReport, "rule has allow and report policy"
	case ModeEnforce:
		d.Result, d.Reason = Deny, "rule has enforce policy"
	case ModeOpen:
		d.Result, d.Reason = Allow, "rule has open enforcement policy"
	default:
		d.Result, d.Reason = Deny, "unexpected policy value"
		err = fmt.Errorf("unexpected policy value for (%s -> %s): %d", args.Service, args.Host, role.role.Mode)
	}

	if d.Default {
		d.Reason = "default rule policy used"
	}

	if d.Result != Allow {
		lists := make([][]Domain, 0, len(role.allow)+len(e.anyAll))
		for _, r := range role.allow {
			lists = append(lists, r.Domains)
		}
		for _, r := range e.anyAll {
			lists = append(lists, r.Domains)
		}
		d.Reason += publicSuffixHint(args.Host, lists...)
	}

	return d, err
}

// mitm returns the MITM config of the first allow rule, in file order, that
// matches host and has one.
func (c *compiledRole) mitm(host string) *MitmConfig {
	for _, r := range c.allow {
		if r.Mitm != nil && matchesAny(host, r.Domains) {
			m := *r.Mitm
			return &m
		}
	}
	return nil
}

func matchesAny(host string, domains []Domain) bool {
	for _, d := range domains {
		if MatchGlob(host, d.Glob, d.CrossPublicSuffix) {
			return true
		}
	}
	return false
}

// LoadFile reads, parses and compiles a v2 ACL file.
func LoadFile(path string, opts Options) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Compile(p, opts)
}
