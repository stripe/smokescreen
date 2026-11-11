package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acl "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
)

func TestNewConfigurationAllowSelfConnections(t *testing.T) {
	tests := []struct {
		name                 string
		yaml                 string
		flags                []string
		allowSelfConnections bool
	}{
		{name: "default", allowSelfConnections: false},
		{name: "omitted in YAML", yaml: "{}", allowSelfConnections: false},
		{name: "enabled in YAML", yaml: "allow_self_connections: true", allowSelfConnections: true},
		{name: "disabled in YAML", yaml: "allow_self_connections: false", allowSelfConnections: false},
		{name: "enabled by CLI", flags: []string{"--allow-self-connections=true"}, allowSelfConnections: true},
		{name: "disabled by CLI", flags: []string{"--allow-self-connections=false"}, allowSelfConnections: false},
		{
			name:                 "CLI enables over YAML",
			yaml:                 "allow_self_connections: false",
			flags:                []string{"--allow-self-connections"},
			allowSelfConnections: true,
		},
		{
			name:                 "CLI disables over YAML",
			yaml:                 "allow_self_connections: true",
			flags:                []string{"--allow-self-connections=false"},
			allowSelfConnections: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"smokescreen"}
			if tt.yaml != "" {
				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0600))
				args = append(args, "--config-file="+path)
			}
			args = append(args, tt.flags...)

			config, err := NewConfiguration(args, nil)
			require.NoError(t, err)
			require.NotNil(t, config)
			assert.Equal(t, tt.allowSelfConnections, config.AllowSelfConnections)
		})
	}
}

const aclWithOpenDefaultRule = `
version: v2
services:
  - name: some-service
    project: test-project
    action: enforce
    allow:
      - domains: ["example.com"]
default:
  project: default-project
  action: open
  allow:
    - domains: ["allowedbydefault.com"]
`

const aclWithOpenNamedRule = `
version: v2
services:
  - name: open-service
    project: test-project
    action: open
default:
  project: default-project
  action: enforce
  allow:
    - domains: ["example.com"]
`

// writeTestConfig writes an ACL file and a top-level smokescreen YAML config
// (referencing it via acl_file) into dir, returning the config file's path.
func writeTestConfig(t *testing.T, dir, aclYAML string) string {
	t.Helper()

	aclPath := filepath.Join(dir, "acl.yaml")
	require.NoError(t, os.WriteFile(aclPath, []byte(aclYAML), 0644))

	configPath := filepath.Join(dir, "config.yaml")
	configYAML := "acl_file: " + aclPath + "\n"
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0644))

	return configPath
}

// TestNewConfigurationRevalidatesYAMLLoadedAcl covers RUN_NET_INFRA-4553:
// a YAML-loaded ACL must be revalidated once disabled actions are known.
func TestNewConfigurationRevalidatesYAMLLoadedAcl(t *testing.T) {
	tests := []struct {
		name      string
		aclYAML   string
		disable   bool
		expectErr bool
	}{
		{
			name:      "default rule using disabled action is rejected",
			aclYAML:   aclWithOpenDefaultRule,
			disable:   true,
			expectErr: true,
		},
		{
			name:      "named rule using disabled action is rejected",
			aclYAML:   aclWithOpenNamedRule,
			disable:   true,
			expectErr: true,
		},
		{
			name:      "same ACL accepted without the disable flag",
			aclYAML:   aclWithOpenDefaultRule,
			disable:   false,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := writeTestConfig(t, dir, tt.aclYAML)

			args := []string{"smokescreen", "--config-file=" + configPath}
			if tt.disable {
				args = append(args, "--disable-acl-policy-action=open")
			}

			conf, err := NewConfiguration(args, nil)

			if tt.expectErr {
				require.Error(t, err)
				require.Nil(t, conf)
			} else {
				require.NoError(t, err)
				require.NotNil(t, conf)
				require.NotNil(t, conf.EgressACL)
			}
		})
	}
}

// TestNewConfigurationEgressAclFileOverridesYAML ensures --egress-acl-file
// still overrides a YAML acl_file that would otherwise fail validation.
func TestNewConfigurationEgressAclFileOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	// The YAML-selected ACL would fail validation with "open" disabled.
	configPath := writeTestConfig(t, dir, aclWithOpenDefaultRule)

	// The CLI-selected ACL does not use "open" anywhere, so it passes.
	cliAclPath := filepath.Join(dir, "cli_acl.yaml")
	require.NoError(t, os.WriteFile(cliAclPath, []byte(`
version: v2
services:
  - name: some-service
    project: test-project
    action: enforce
    allow:
      - domains: ["example.com"]
default:
  project: default-project
  action: enforce
  allow:
    - domains: ["example.com"]
`), 0644))

	args := []string{
		"smokescreen",
		"--config-file=" + configPath,
		"--egress-acl-file=" + cliAclPath,
		"--disable-acl-policy-action=open",
	}

	conf, err := NewConfiguration(args, nil)
	require.NoError(t, err)
	require.NotNil(t, conf)
	require.NotNil(t, conf.EgressACL)
}

// TestNewConfigurationAclLoadOptions covers the switches that loosen how the
// egress ACL loads. --acl-compat lets a service allow entry that overlaps the
// global deny list without override_global_policy win, and
// --acl-allow-unknown-fields ignores keys that the v2 format does not define.
// Each also works as a config file key, which is read before the CLI flags. A
// v1 file loads through the converter to v2.
func TestNewConfigurationAclLoadOptions(t *testing.T) {
	const unmarked = `
version: v2
services:
  - name: ci
    action: enforce
    allow:
      - domains: [pypi.org]
global:
  deny: [pypi.org]
`
	const v1File = `
version: v1
services:
  - name: ci
    project: ci
    action: enforce
    owner: ci-team
    allowed_domains: [pypi.org]
global_deny_list: [pypi.org]
`
	const unknownField = `
version: v2
services:
  - name: ci
    action: enforce
    owner: ci-team
    allow:
      - domains: [pypi.org]
`
	for _, tt := range []struct {
		name, acl, configYAML string
		flags                 []string
		err                   string
	}{
		{name: "overlap without compat", acl: unmarked, err: "set override_global_policy: true"},
		{name: "CLI compat", acl: unmarked, flags: []string{"--acl-compat"}},
		{name: "YAML compat", acl: unmarked, configYAML: "acl_compat: true\n"},
		{name: "CLI allow unknown fields", acl: unknownField, flags: []string{"--acl-allow-unknown-fields"}},
		{name: "YAML allow unknown fields", acl: unknownField, configYAML: "acl_allow_unknown_fields: true\n"},
		// A v1 file loads through the converter, with v1's lenient parsing and
		// its precedence: the service allow wins over the global deny list.
		{name: "v1 file", acl: v1File},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			aclPath := filepath.Join(dir, "acl.yaml")
			require.NoError(t, os.WriteFile(aclPath, []byte(tt.acl), 0644))
			args := append([]string{"smokescreen", "--egress-acl-file=" + aclPath}, tt.flags...)
			if tt.configYAML != "" {
				configPath := filepath.Join(dir, "config.yaml")
				require.NoError(t, os.WriteFile(configPath, []byte(tt.configYAML+"acl_file: "+aclPath+"\n"), 0644))
				args = []string{"smokescreen", "--config-file=" + configPath}
			}

			conf, err := NewConfiguration(args, nil)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			d, err := conf.EgressACL.Decide(acl.DecideArgs{Service: "ci", Host: "pypi.org"})
			require.NoError(t, err)
			assert.Equal(t, acl.Allow, d.Result)
		})
	}
}

func TestNewConfigurationMostSpecificIPRules(t *testing.T) {
	for _, tt := range []struct {
		name, yaml string
		flags      []string
		want       bool
		invalid    bool
	}{
		{name: "default"},
		{name: "omitted YAML", yaml: "{}"},
		{name: "enabled YAML", yaml: "most_specific_ip_rules: true", want: true},
		{name: "disabled YAML", yaml: "most_specific_ip_rules: false"},
		{name: "enabled CLI", flags: []string{"--most-specific-ip-rules"}, want: true},
		{name: "disabled CLI", flags: []string{"--most-specific-ip-rules=false"}},
		{name: "CLI disables YAML", yaml: "most_specific_ip_rules: true", flags: []string{"--most-specific-ip-rules=false"}},
		{name: "CLI enables YAML", yaml: "most_specific_ip_rules: false", flags: []string{"--most-specific-ip-rules"}, want: true},
		{name: "invalid YAML", yaml: "most_specific_ip_rules: typo", invalid: true},
		{name: "invalid CLI", flags: []string{"--most-specific-ip-rules=typo"}, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"smokescreen"}
			if tt.yaml != "" {
				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0600))
				args = append(args, "--config-file="+path)
			}
			args = append(args, tt.flags...)
			config, err := NewConfiguration(args, nil)
			if tt.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, config.MostSpecificIPRules)
			}
		})
	}
}

func TestNewConfigurationResolverAddresses(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		flags   []string
		wantErr bool
	}{
		{name: "system resolver"},
		{name: "single CLI", flags: []string{"--resolver-address", "127.0.0.1:53"}},
		{name: "multiple CLI", flags: []string{"--resolver-address", "127.0.0.1:53", "--resolver-address", "127.0.0.2:53"}},
		{name: "multiple YAML", yaml: "resolver_addresses: [127.0.0.1:53, '127.0.0.2:53']"},
		{name: "invalid CLI", flags: []string{"--resolver-address", "127.0.0.1:53", "--resolver-address", "invalid"}, wantErr: true},
		{name: "invalid YAML", yaml: "resolver_addresses: [127.0.0.1:53, invalid]", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"smokescreen"}
			if tt.yaml != "" {
				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0600))
				args = append(args, "--config-file", path)
			}
			args = append(args, tt.flags...)
			config, err := NewConfiguration(args, nil)
			if tt.wantErr {
				require.ErrorContains(t, err, "invalid resolver address")
				require.Nil(t, config)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, config)
		})
	}
}
