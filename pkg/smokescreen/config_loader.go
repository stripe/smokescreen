package smokescreen

import (
	"errors"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type yamlConfigTls struct {
	CertFile      string   `yaml:"cert_file"`
	KeyFile       string   `yaml:"key_file"`
	ClientCAFiles []string `yaml:"client_ca_files"`
	CRLFiles      []string `yaml:"crl_files"`
}

type yamlConfig struct {
	Ip                   string
	// use a pointer here so we can distinguish unset vs explicit zero, as we
	// may be overriding a non-zero default
	Port                 *uint16
	DenyRanges           []string      `yaml:"deny_ranges"`
	AllowRanges          []string      `yaml:"allow_ranges"`
	ConnectTimeout       time.Duration `yaml:"connect_timeout"`
	ExitTimeout          time.Duration `yaml:"exit_timeout"`
	MaintenanceFile      string        `yaml:"maintenance_file"`
	StatsdAddress        string        `yaml:"statsd_address"`
	EgressAclFile        string        `yaml:"acl_file"`
	SupportProxyProtocol bool          `yaml:"support_proxy_protocol"`
	DenyMessageExtra     string        `yaml:"deny_message_extra"`
	AllowMissingRole     bool          `yaml:"allow_missing_role"`

	Tls                  *yamlConfigTls

	// Currently not configurable via YAML: RoleFromRequest, Log, DisabledAclPolicyActions
}

func UnmarshalConfig(rawYaml []byte) (*Config, error) {
	var yc yamlConfig
	c := NewConfig()

	err := yaml.UnmarshalStrict(rawYaml, &yc)
	if err != nil {
		return c, err
	}

	c.Ip = yc.Ip

	if yc.Port != nil {
		c.Port = *yc.Port
	}

	err = c.SetDenyRanges(yc.DenyRanges)
	if err != nil {
		return c, err
	}

	err = c.SetAllowRanges(yc.AllowRanges)
	if err != nil {
		return c, err
	}

	c.ConnectTimeout = yc.ConnectTimeout
	c.ExitTimeout = yc.ExitTimeout

	c.MaintenanceFile = yc.MaintenanceFile
	if c.MaintenanceFile != "" {
		if _, err = os.Stat(c.MaintenanceFile); err != nil {
			return c, err
		}
	}

	err = c.SetupStatsd(yc.StatsdAddress)
	if err != nil {
		return c, err
	}

	if yc.EgressAclFile != "" {
		err = c.SetupEgressAcl(yc.EgressAclFile)
		if err != nil {
			return c, err
		}
	}

	c.SupportProxyProtocol = yc.SupportProxyProtocol

	if yc.Tls != nil {
		if yc.Tls.CertFile == "" {
			return c, errors.New("'tls' section requires 'cert_file'")
		}

		key_file := yc.Tls.KeyFile
		if key_file == "" {
			// Assume CertFile is a cert+key bundle
			key_file = yc.Tls.CertFile
		}

		err = c.SetupTls(yc.Tls.CertFile, key_file, yc.Tls.ClientCAFiles)
		if err != nil {
			return c, err
		}

		c.SetupCrls(yc.Tls.CRLFiles)
	}

	c.AllowMissingRole = yc.AllowMissingRole
	c.AdditionalErrorMessageOnDeny = yc.DenyMessageExtra

	return c, nil
}

func LoadConfig(filePath string) (*Config, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	config, err := UnmarshalConfig(bytes)
	if err != nil {
		return nil, err
	}

	return config, nil
}
