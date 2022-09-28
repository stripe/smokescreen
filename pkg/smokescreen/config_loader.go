package smokescreen

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v2"
)

type yamlConfigTls struct {
	CertFile      string   `yaml:"cert_file"`
	KeyFile       string   `yaml:"key_file"`
	ClientCAFiles []string `yaml:"client_ca_files"`
	CRLFiles      []string `yaml:"crl_files"`
}

// Port and ExitTimeout use a pointer so we can distinguish unset vs explicit
// zero, to avoid overriding a non-zero default when the value is not set.
type yamlConfig struct {
	Ip                   string
	Port                 *uint16
	DenyRanges           []string `yaml:"deny_ranges"`
	AllowRanges          []string `yaml:"allow_ranges"`
	Resolvers            []string `yaml:"resolver_addresses"`
	StatsdAddress        string   `yaml:"statsd_address"`
	EgressAclFile        string   `yaml:"acl_file"`
	SupportProxyProtocol bool     `yaml:"support_proxy_protocol"`
	DenyMessageExtra     string   `yaml:"deny_message_extra"`
	AllowMissingRole     bool     `yaml:"allow_missing_role"`
	Network              string   `yaml:"network"`

	ConnectTimeout time.Duration  `yaml:"connect_timeout"`
	IdleTimeout    time.Duration  `yaml:"idle_timeout"`
	ExitTimeout    *time.Duration `yaml:"exit_timeout"`

	StatsSocketDir      string `yaml:"stats_socket_dir"`
	StatsSocketFileMode string `yaml:"stats_socket_file_mode"`

	TransportMaxIdleConns        int `yaml:"transport_max_idle_conns"`
	TransportMaxIdleConnsPerHost int `yaml:"transport_max_idle_conns_per_host"`

	TimeConnect bool `yaml:"time_connect"`

	Tls *yamlConfigTls
	// Currently not configurable via YAML: RoleFromRequest, Log, DisabledAclPolicyActions

	UnsafeAllowPrivateRanges bool `yaml:"unsafe_allow_private_ranges"`
}

func (config *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yc yamlConfig
	*config = *NewConfig()

	err := unmarshal(&yc)
	if err != nil {
		return err
	}

	config.Ip = yc.Ip

	if yc.Port != nil {
		config.Port = *yc.Port
	}

	err = config.SetDenyRanges(yc.DenyRanges)
	if err != nil {
		return err
	}

	err = config.SetAllowRanges(yc.AllowRanges)
	if err != nil {
		return err
	}

	err = config.SetResolverAddresses(yc.Resolvers)
	if err != nil {
		return err
	}

	config.IdleTimeout = yc.IdleTimeout
	config.ConnectTimeout = yc.ConnectTimeout
	if yc.ExitTimeout != nil {
		config.ExitTimeout = *yc.ExitTimeout
	}

	err = config.SetupStatsd(yc.StatsdAddress)
	if err != nil {
		return err
	}

	if yc.EgressAclFile != "" {
		err = config.SetupEgressAcl(yc.EgressAclFile)
		if err != nil {
			return err
		}
	}

	config.SupportProxyProtocol = yc.SupportProxyProtocol

	if yc.StatsSocketDir != "" {
		config.StatsSocketDir = yc.StatsSocketDir
	}

	if yc.StatsSocketFileMode != "" {
		filemode, err := strconv.ParseInt(yc.StatsSocketFileMode, 8, 9)

		if err != nil {
			config.Log.Fatal(err)
		}

		config.StatsSocketFileMode = os.FileMode(filemode)
	}

	if yc.Tls != nil {
		if yc.Tls.CertFile == "" {
			return errors.New("'tls' section requires 'cert_file'")
		}

		key_file := yc.Tls.KeyFile
		if key_file == "" {
			// Assume CertFile is a cert+key bundle
			key_file = yc.Tls.CertFile
		}

		err = config.SetupTls(yc.Tls.CertFile, key_file, yc.Tls.ClientCAFiles)
		if err != nil {
			return err
		}

		err = config.SetupCrls(yc.Tls.CRLFiles)
		if err != nil {
			return err
		}
	}

	if yc.Network != "" {
		switch yc.Network {
		case "ip", "ip4", "ip6":
		default:
			return fmt.Errorf("invalid network type: %v", yc.Network)
		}
		config.Network = yc.Network
	}

	config.AllowMissingRole = yc.AllowMissingRole
	config.AdditionalErrorMessageOnDeny = yc.DenyMessageExtra
	config.TimeConnect = yc.TimeConnect
	config.UnsafeAllowPrivateRanges = yc.UnsafeAllowPrivateRanges

	return nil
}

func LoadConfig(filePath string) (*Config, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := yaml.UnmarshalStrict(bytes, config); err != nil {
		return nil, err
	}

	return config, nil
}
