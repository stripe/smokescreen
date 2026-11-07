package acl

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
)

// DecideArgs holds the arguments for an ACL decision. Using a struct keeps the
// Decider interface stable as new fields are added (e.g. Req for request-aware
// authorization in custom Decider implementations). The Engine does not inspect
// Req or ConnectReq; they are provided solely for use by custom implementations.
type DecideArgs struct {
	Req *http.Request
	// ConnectReq is the edge CONNECT request from the client when Decide is
	// evaluating a MITM inner HTTP request.
	ConnectReq       *http.Request
	Service          string
	Host             string
	ConnectProxyHost string
}

// Decider decides whether a request may reach its destination.
type Decider interface {
	Decide(args DecideArgs) (Decision, error)
}

// Decision is the result of an ACL check.
type Decision struct {
	Reason     string
	Default    bool
	Result     DecisionResult
	Project    string
	MitmConfig *MitmConfig
}

// DecisionResult represents the result of checking the ACL.
type DecisionResult int

// Possible decision results.
const (
	Allow DecisionResult = iota
	AllowAndReport
	Deny
)

func (d DecisionResult) String() string {
	return [...]string{"Allow", "AllowAndReport", "Deny"}[d]
}

// Engine decides requests with a compiled Policy. It does not change after
// Compile returns, so it is safe for concurrent use.
type Engine struct {
	services    map[string]*Service
	def         *Service
	globalDeny  []string
	globalAllow []Entry
	compat      bool
}

// Compile validates p and builds an Engine from a copy of it.
func Compile(p *Policy, opts Options) (*Engine, error) {
	if err := p.Validate(opts); err != nil {
		return nil, err
	}
	return newEngine(p, opts.Compat), nil
}

// newEngine builds an Engine from a copy of p without validating it first.
// Compile is the only exported way to get an Engine, so that every Engine in
// production has gone through Validate; this split lets a test build one from
// a policy that Validate would reject, to check Decide's own defenses.
func newEngine(p *Policy, compat bool) *Engine {
	e := &Engine{
		services:    make(map[string]*Service, len(p.Services)),
		globalDeny:  slices.Clone(p.Global.Deny),
		globalAllow: cloneEntries(p.Global.Allow),
		compat:      compat,
	}
	for _, s := range p.Services {
		c := cloneService(s)
		e.services[s.Name] = &c
	}
	if p.Default != nil {
		c := cloneService(*p.Default)
		e.def = &c
	}
	return e
}

// Load reads, joins and compiles v2 ACL files.
func Load(opts Options, paths ...string) (*Engine, error) {
	p, err := LoadFiles(opts, paths...)
	if err != nil {
		return nil, err
	}
	return Compile(p, opts)
}

// Decide applies the policy to one request:
//  1. A role that has no service uses the default service, or is denied if
//     there is none.
//  2. A CONNECT proxy host must match one of the service's proxies.
//  3. The service's deny list, then its allow entries. A matching allow entry
//     wins over the global deny list only if a matching allow entry sets
//     OverrideGlobalPolicy, or in compat mode.
//  4. The global deny list, then the global allow entries.
//  5. The service's action.
//
// The order of entries in the files does not change a result. It only picks
// the MITM config when several matching allow entries have one.
func (e *Engine) Decide(args DecideArgs) (Decision, error) {
	var d Decision

	s, ok := e.services[args.Service]
	if !ok {
		s = e.def
		d.Default = true
	}
	if s == nil {
		return Decision{Result: Deny, Reason: "no rule matched"}, nil
	}
	d.Project = s.Project

	if args.ConnectProxyHost != "" && !matchesAny(args.ConnectProxyHost, s.Proxies, false) {
		d.Result = Deny
		d.Reason = "connect proxy host not allowed in rule" + publicSuffixHint(args.ConnectProxyHost, s.Proxies)
		return d, nil
	}

	if matchesDeny(args.Host, s.Deny) {
		d.Result, d.Reason = Deny, "host matched denied domain in rule"
		return d, nil
	}
	if matched, override := matchAllow(args.Host, s.Allow); matched {
		// Outside compat mode, Validate rejects an allow entry that overlaps
		// the global deny list without OverrideGlobalPolicy, but its overlap
		// check is a static approximation. Checking the concrete host here is
		// exact, and catches anything the static check missed.
		if !override && !e.compat && matchesDeny(args.Host, e.globalDeny) {
			d.Result, d.Reason = Deny, "host matched rule in global deny list"
			return d, nil
		}
		d.Result, d.Reason = Allow, "host matched allowed domain in rule"
		d.MitmConfig = mitmFor(args.Host, s.Allow)
		return d, nil
	}
	if matchesDeny(args.Host, e.globalDeny) {
		d.Result, d.Reason = Deny, "host matched rule in global deny list"
		return d, nil
	}
	if matchesEntry(args.Host, e.globalAllow) != nil {
		d.Result, d.Reason = Allow, "host matched rule in global allow list"
		return d, nil
	}

	var err error
	switch s.Action {
	case ModeReport:
		d.Result, d.Reason = AllowAndReport, "rule has allow and report policy"
	case ModeEnforce:
		d.Result, d.Reason = Deny, "rule has enforce policy"
	case ModeOpen:
		d.Result, d.Reason = Allow, "rule has open enforcement policy"
	default:
		d.Result, d.Reason = Deny, "unexpected policy value"
		err = fmt.Errorf("unexpected policy value for (%s -> %s): %d", args.Service, args.Host, s.Action)
	}
	if d.Default {
		d.Reason = "default rule policy used"
	}
	if d.Result != Allow {
		lists := make([][]string, 0, len(s.Allow)+len(e.globalAllow))
		for _, en := range s.Allow {
			lists = append(lists, en.Domains)
		}
		for _, en := range e.globalAllow {
			lists = append(lists, en.Domains)
		}
		d.Reason += publicSuffixHint(args.Host, lists...)
	}
	return d, err
}

func matchesEntry(host string, entries []Entry) *Entry {
	for i := range entries {
		if entries[i].matches(host) {
			return &entries[i]
		}
	}
	return nil
}

// matchAllow reports whether an allow entry matches host, and whether one of
// the matching entries sets OverrideGlobalPolicy.
func matchAllow(host string, allow []Entry) (matched, override bool) {
	for i := range allow {
		if allow[i].matches(host) {
			matched = true
			if allow[i].OverrideGlobalPolicy {
				return true, true
			}
		}
	}
	return matched, false
}

// matchesDeny reports whether host matches one of the deny globs. Deny globs
// always match across public suffixes.
func matchesDeny(host string, globs []string) bool {
	return matchesAny(host, globs, true)
}

// matches reports whether host matches one of the entry's domains, with the
// entry's own CrossPublicSuffix setting.
func (en *Entry) matches(host string) bool {
	return matchesAny(host, en.Domains, en.CrossPublicSuffix)
}

func matchesAny(host string, globs []string, crossPublicSuffix bool) bool {
	for _, g := range globs {
		if MatchGlob(host, g, crossPublicSuffix) {
			return true
		}
	}
	return false
}

// mitmFor returns a clone of the MITM config of the first allow entry, in
// file order, that matches host and has one. This searches independently of
// which entry decided the allow, so a host that matches two overlapping
// entries, one with a MITM config and one without, still gets it.
func mitmFor(host string, allow []Entry) *MitmConfig {
	for i := range allow {
		if allow[i].Mitm != nil && allow[i].matches(host) {
			return cloneMitmConfig(allow[i].Mitm)
		}
	}
	return nil
}

func cloneService(s Service) Service {
	s.Proxies = slices.Clone(s.Proxies)
	s.Allow = cloneEntries(s.Allow)
	s.Deny = slices.Clone(s.Deny)
	return s
}

func cloneEntries(entries []Entry) []Entry {
	out := slices.Clone(entries)
	for i := range out {
		out[i].Domains = slices.Clone(out[i].Domains)
		out[i].Mitm = cloneMitmConfig(out[i].Mitm)
	}
	return out
}

// cloneMitmConfig deep-copies m, or returns nil if m is nil. Decide calls this
// again for the MitmConfig in a returned Decision, on top of the clone that
// Compile already made for the Engine's own copy: *m alone would still share
// AddHeaders and DetailedHttpLogsFullHeaders with it, since both are
// reference types, so a caller mutating one Decision's MitmConfig would
// corrupt every later decision that returns the same entry's config.
func cloneMitmConfig(m *MitmConfig) *MitmConfig {
	if m == nil {
		return nil
	}
	c := *m
	c.AddHeaders = maps.Clone(m.AddHeaders)
	c.DetailedHttpLogsFullHeaders = slices.Clone(m.DetailedHttpLogsFullHeaders)
	return &c
}
