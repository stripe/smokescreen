package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfigurationSelfConnectionPorts(t *testing.T) {
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
version: v1
services:
  - name: some-service
    project: test-project
    action: enforce
    allowed_domains:
      - "example.com"
default:
  project: default-project
  action: open
  allowed_domains:
    - "allowedbydefault.com"
`

const aclWithOpenNamedRule = `
version: v1
services:
  - name: open-service
    project: test-project
    action: open
default:
  project: default-project
  action: enforce
  allowed_domains:
    - "example.com"
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
version: v1
services:
  - name: some-service
    project: test-project
    action: enforce
    allowed_domains:
      - "example.com"
default:
  project: default-project
  action: enforce
  allowed_domains:
    - "example.com"
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
