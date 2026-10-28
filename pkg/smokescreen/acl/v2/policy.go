package acl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

// Version is the value of the version key in a v2 ACL file.
const Version = "v2"

// Policy is a v2 ACL. Services say what each role may and may not reach.
// Global entries apply to every role.
type Policy struct {
	Version  string    `yaml:"version"`
	Services []Service `yaml:"services"`
	// Default applies to roles that are not in Services. If it is nil, those
	// roles are denied.
	Default *Service `yaml:"default"`
	Global  Global   `yaml:"global"`
}

// Service is the ACL for one role. For the default service, Name is empty.
type Service struct {
	Name    string `yaml:"name"`
	Project string `yaml:"project"`
	// Action decides requests that no entry matches.
	Action Mode `yaml:"action"`
	// Proxies are the upstream proxies that the role may CONNECT through.
	Proxies []Domain `yaml:"proxies"`
	Allow   []Entry  `yaml:"allow"`
	// Deny holds domain globs that the role may not reach. Deny globs always
	// match across public suffixes, so a deny list is as broad as it reads.
	Deny []string `yaml:"deny"`
}

// Global holds entries that apply to every role.
type Global struct {
	Allow []Entry `yaml:"allow"`
	// Deny holds domain globs that no role may reach, unless a service allow
	// entry that matches the host sets OverrideGlobalPolicy. Deny globs
	// always match across public suffixes.
	Deny []string `yaml:"deny"`
}

// Entry is a set of allowed domains and the options that apply to them.
type Entry struct {
	Domains []Domain `yaml:"domains"`
	// Mitm applies to requests that this entry allows. Only service allow
	// entries can have it.
	Mitm *MitmConfig `yaml:"mitm"`
	// OverrideGlobalPolicy lets this service allow entry win over the global
	// deny list for the hosts that the entry matches. Only service allow
	// entries can set it. Validation requires it on every service allow entry
	// that overlaps the global deny list, so that each exception is visible
	// where it is made.
	OverrideGlobalPolicy bool `yaml:"override_global_policy"`
}

// Domain is a domain glob. In a file it is either a string or a mapping with
// glob and cross_public_suffix keys.
type Domain struct {
	Glob string `yaml:"glob"`
	// CrossPublicSuffix lets a label wildcard match hosts outside the glob's
	// registrable domain. See MatchGlob.
	CrossPublicSuffix bool `yaml:"cross_public_suffix"`
}

// UnmarshalYAML accepts a plain string as a Domain with only a glob, or a
// mapping with glob and cross_public_suffix keys. Node.Decode does not inherit
// the decoder's KnownFields setting, so the mapping form rejects unknown keys
// itself.
func (d *Domain) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&d.Glob)
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("a domain must be a string or a mapping, not %v", n.Tag)
	}
	for i := 0; i < len(n.Content); i += 2 {
		switch key := n.Content[i].Value; key {
		case "glob", "cross_public_suffix":
		default:
			return fmt.Errorf("field %s not found in type acl.Domain", key)
		}
	}
	type plain Domain
	return n.Decode((*plain)(d))
}

// MitmConfig configures how a MITM request is handled.
type MitmConfig struct {
	AddHeaders                  map[string]string `yaml:"add_headers"`
	DetailedHttpLogs            bool              `yaml:"detailed_http_logs"`
	DetailedHttpLogsFullHeaders []string          `yaml:"detailed_http_logs_full_headers"`
}

// Mode is what happens to a request from a role when no entry matches it.
type Mode int

// Possible modes.
const (
	ModeUnknown Mode = iota
	ModeOpen
	ModeReport
	ModeEnforce
)

// Modes maps the action names used in ACL files to modes.
var Modes = map[string]Mode{
	"open":    ModeOpen,
	"report":  ModeReport,
	"enforce": ModeEnforce,
}

func (m Mode) String() string {
	return [...]string{"Unknown", "Open", "Report", "Enforce"}[m]
}

// ModeFromString returns the mode for an action name used in ACL files.
func ModeFromString(s string) (Mode, error) {
	if m, ok := Modes[s]; ok {
		return m, nil
	}
	return ModeUnknown, fmt.Errorf("unknown action %v", s)
}

// UnmarshalYAML reads an action name.
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

// MarshalYAML writes the action name that ModeFromString accepts for m, so
// that a policy round-trips through yaml.Marshal and Parse. Without this, the
// default int marshaling would write a number that Parse then rejects.
func (m Mode) MarshalYAML() (interface{}, error) {
	for name, mode := range Modes {
		if mode == m {
			return name, nil
		}
	}
	return nil, fmt.Errorf("unknown action %d", m)
}

// Parse decodes one v2 ACL file. Unknown keys are an error, and so is a
// second "---" document in the file, which Decode would otherwise silently
// ignore.
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
	var extra yaml.Node
	switch err := dec.Decode(&extra); err {
	case io.EOF:
	case nil:
		return nil, errors.New("file has more than one YAML document")
	default:
		return nil, err
	}
	return &p, nil
}

// Join combines policies from several files into one. Services and global
// entries are concatenated; at most one policy may set Default.
func Join(policies ...*Policy) (*Policy, error) {
	out := &Policy{Version: Version}
	for _, p := range policies {
		out.Services = append(out.Services, p.Services...)
		out.Global.Allow = append(out.Global.Allow, p.Global.Allow...)
		out.Global.Deny = append(out.Global.Deny, p.Global.Deny...)
		if p.Default != nil {
			if out.Default != nil {
				return nil, errors.New("default is defined more than once")
			}
			out.Default = p.Default
		}
	}
	return out, nil
}

// LoadFiles reads, parses and joins v2 ACL files.
func LoadFiles(paths ...string) (*Policy, error) {
	policies := make([]*Policy, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		policies = append(policies, p)
	}
	return Join(policies...)
}
