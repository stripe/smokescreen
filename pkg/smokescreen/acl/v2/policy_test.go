package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestParse(t *testing.T) {
	p, err := Parse([]byte(`
version: v2
services:
  - name: ci
    action: open
    allow:
      - domains: [pypi.org, {glob: "regis*.npmjs.org", cross_public_suffix: true}]
`))
	require.NoError(t, err)
	assert.Equal(t, []Domain{{Glob: "pypi.org"}, {Glob: "regis*.npmjs.org", CrossPublicSuffix: true}}, p.Services[0].Allow[0].Domains)
	assert.Equal(t, ModeOpen, p.Services[0].Action)

	// A policy round-trips: tooling that loads, edits and writes one back
	// must get YAML that Parse accepts, not the Mode's bare int value.
	for _, mode := range []Mode{ModeOpen, ModeReport, ModeEnforce} {
		out, err := yaml.Marshal(&Policy{Version: Version, Services: []Service{{Name: "a", Action: mode}}})
		require.NoError(t, err)
		back, err := Parse(out)
		require.NoError(t, err, "marshaled:\n%s", out)
		assert.Equal(t, mode, back.Services[0].Action)
	}

	for doc, want := range map[string]string{
		"version: v2\nservices: []\nglobal_deny_list: []\n": "field global_deny_list not found",
		"version: v1\n": `expected version "v2" got "v1"`,
		"version: v2\nservices: [{name: a, action: closed}]\n":                                                          "unknown action closed",
		"version: v2\nservices: [{name: a, action: open, allow: [{domains: [{glob: x, cross_public_sufix: true}]}]}]\n": "field cross_public_sufix not found",
		"version: v2\nservices: []\n---\nversion: v2\nglobal: {deny: [x]}\n":                                            "more than one YAML document",
		"version: v2\nglobal: {deny: [{glob: x, cross_public_suffix: true}]}\n":                                         "cannot unmarshal !!map into string",
	} {
		_, err := Parse([]byte(doc))
		require.ErrorContains(t, err, want)
	}
}

func TestValidate(t *testing.T) {
	deny := []string{"*.example.com"}
	allow := Entry{Domains: []Domain{{Glob: "api.example.com"}}}
	override := Entry{Domains: allow.Domains, OverrideGlobalPolicy: true}
	svc := func(allow ...Entry) Service { return Service{Name: "web", Action: ModeEnforce, Allow: allow} }

	tests := []struct {
		name string
		p    Policy
		opts Options
		err  string
	}{
		{"duplicate service", Policy{Services: []Service{svc(), svc()}}, Options{}, `service "web" is defined more than once`},
		{"missing action", Policy{Services: []Service{{Name: "web"}}}, Options{}, "web: action is required"},
		{"disabled action", Policy{Services: []Service{svc()}}, Options{DisabledModes: []Mode{ModeEnforce}}, "utilizes a disabled policy:Enforce"},
		{"empty domains", Policy{Services: []Service{svc(Entry{})}}, Options{}, "web: allow[0]: domains must not be empty"},
		{"invalid glob", Policy{Services: []Service{svc(Entry{Domains: []Domain{{Glob: "*"}}})}}, Options{}, "must not match everything"},
		{"invalid deny glob", Policy{Global: Global{Deny: []string{"*"}}}, Options{}, "global.deny: *: domain glob must not match everything"},
		{"override on global allow", Policy{Global: Global{Allow: []Entry{override}}}, Options{}, "only allowed on service allow entries"},
		{"overlap without override", Policy{Services: []Service{svc(allow)}, Global: Global{Deny: deny}}, Options{}, `web: allow[0]: overlaps global deny "*.example.com"; set override_global_policy: true`},
		// Deny globs cross public suffixes, so this deny also covers an S3
		// bucket host that an allow glob of the same text would not match.
		{"deny glob crosses public suffixes", Policy{Services: []Service{svc(Entry{Domains: []Domain{{Glob: "access-analyzer.s3.amazonaws.com"}}})}, Global: Global{Deny: []string{"access-analyzer.*.amazonaws.com"}}}, Options{}, "overlaps global deny"},
		{"default with a name", Policy{Default: &Service{Name: "x", Action: ModeEnforce}}, Options{}, "default: name is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, tt.p.Validate(tt.opts), tt.err)
		})
	}

	ok := Policy{Services: []Service{svc(override)}, Global: Global{Deny: deny}}
	require.NoError(t, ok.Validate(Options{}))

	// Compat mode loads an unmarked overlap and reports it.
	var warnings []string
	compat := Policy{Services: []Service{svc(allow)}, Global: Global{Deny: deny}}
	require.NoError(t, compat.Validate(Options{Compat: true, Warn: func(m string) { warnings = append(warnings, m) }}))
	assert.Equal(t, []string{`web: allow[0]: overlaps global deny "*.example.com" without override_global_policy; allowed in compat mode`}, warnings)
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}
	shared := write("shared.yaml", "version: v2\ndefault: {action: enforce}\nglobal:\n  allow: [{domains: [api.example.com]}]\n")
	web := write("web.yaml", "version: v2\nservices: [{name: web, action: enforce}]\n")

	p, err := LoadFiles(shared, web)
	require.NoError(t, err)
	assert.Len(t, p.Services, 1)
	assert.NotNil(t, p.Default)
	assert.Len(t, p.Global.Allow, 1)

	_, err = LoadFiles(shared, shared)
	require.ErrorContains(t, err, "default is defined more than once")
}
