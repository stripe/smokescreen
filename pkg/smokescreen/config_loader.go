package smokescreen

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/stripe/goproxy"
	"gopkg.in/yaml.v2"
)

type yamlConfigTls struct {
	CertFile      string   `yaml:"cert_file"`
	KeyFile       string   `yaml:"key_file"`
	ClientCAFiles []string `yaml:"client_ca_files"`
	CRLFiles      []string `yaml:"crl_files"`
}

// Scalar pointers distinguish omitted keys from explicit zero or false values.
type yamlConfig struct {
	Ip                   *string
	Port                 *uint16
	DenyRanges           []string `yaml:"deny_ranges"`
	AllowRanges          []string `yaml:"allow_ranges"`
	DenyAddresses        []string `yaml:"deny_addresses"`
	AllowAddresses       []string `yaml:"allow_addresses"`
	Resolvers            []string `yaml:"resolver_addresses"`
	StatsdAddress        *string  `yaml:"statsd_address"`
	EgressAclFile        *string  `yaml:"acl_file"`
	SupportProxyProtocol *bool    `yaml:"support_proxy_protocol"`
	DenyMessageExtra     *string  `yaml:"deny_message_extra"`
	AllowMissingRole     *bool    `yaml:"allow_missing_role"`
	Network              *string  `yaml:"network"`

	ConnectTimeout *time.Duration `yaml:"connect_timeout"`
	IdleTimeout    *time.Duration `yaml:"idle_timeout"`
	ExitTimeout    *time.Duration `yaml:"exit_timeout"`

	// HTTP server timeouts to prevent DoS attacks
	ReadHeaderTimeout *time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       *time.Duration `yaml:"read_timeout"`
	WriteTimeout      *time.Duration `yaml:"write_timeout"`

	StatsSocketDir      *string `yaml:"stats_socket_dir"`
	StatsSocketFileMode *string `yaml:"stats_socket_file_mode"`

	TransportMaxIdleConns        *int `yaml:"transport_max_idle_conns"`
	TransportMaxIdleConnsPerHost *int `yaml:"transport_max_idle_conns_per_host"`

	TimeConnect *bool `yaml:"time_connect"`

	Tls *yamlConfigTls
	// Currently not configurable via YAML: RoleFromRequest, Log, DisabledAclPolicyActions

	UnsafeAllowPrivateRanges *bool  `yaml:"unsafe_allow_private_ranges"`
	MitmCaCertFile           string `yaml:"mitm_ca_cert_file"`
	MitmCaKeyFile            string `yaml:"mitm_ca_key_file"`

	// Rate and concurrency limiting
	MaxConcurrentRequests *int     `yaml:"max_concurrent_requests"`
	MaxRequestRate        *float64 `yaml:"max_request_rate"`
	MaxRequestBurst       *int     `yaml:"max_request_burst"`

	// Tunnel limiting (for long-lived CONNECT connections)
	MaxConcurrentConnectTunnels *int `yaml:"max_concurrent_connect_tunnels"`

	DNSTimeout *time.Duration `yaml:"dns_timeout"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yc yamlConfig
	if err := unmarshal(&yc); err != nil {
		return err
	}

	if c.Log == nil {
		c.Log = NewConfig().Log
	}
	if c.Resolver == nil {
		c.Resolver = &net.Resolver{}
	}
	c.applyYAMLValues(yc)
	if err := c.applyYAMLRules(yc); err != nil {
		return err
	}
	if yc.Resolvers != nil {
		if len(yc.Resolvers) == 0 {
			c.Resolver = &net.Resolver{}
		} else if err := c.SetResolverAddresses(yc.Resolvers); err != nil {
			return err
		}
	}
	if yc.StatsdAddress != nil || c.MetricsClient == nil {
		var address string
		setYAMLValue(&address, yc.StatsdAddress)
		if err := c.SetupStatsd(address); err != nil {
			return err
		}
	}
	if yc.EgressAclFile != nil {
		if *yc.EgressAclFile == "" {
			c.EgressACL = nil
		} else if err := c.SetupEgressAcl(*yc.EgressAclFile); err != nil {
			return err
		}
	}
	if yc.StatsSocketFileMode != nil {
		filemode, err := strconv.ParseInt(*yc.StatsSocketFileMode, 8, 9)
		if err != nil {
			return fmt.Errorf("invalid stats_socket_file_mode: %w", err)
		}
		c.StatsSocketFileMode = os.FileMode(filemode)
	}
	if err := c.applyYAMLTLS(yc.Tls); err != nil {
		return err
	}
	if yc.Network != nil {
		switch *yc.Network {
		case "ip", "ip4", "ip6":
		default:
			return fmt.Errorf("invalid network type: %v", *yc.Network)
		}
		c.Network = *yc.Network
	}
	if err := c.applyYAMLMITM(yc.MitmCaCertFile, yc.MitmCaKeyFile); err != nil {
		return err
	}
	return c.applyYAMLRateLimits(yc)
}

func setYAMLValue[T any](destination *T, value *T) {
	if value != nil {
		*destination = *value
	}
}

func (c *Config) applyYAMLValues(yc yamlConfig) {
	setYAMLValue(&c.Ip, yc.Ip)
	setYAMLValue(&c.Port, yc.Port)
	setYAMLValue(&c.IdleTimeout, yc.IdleTimeout)
	setYAMLValue(&c.ConnectTimeout, yc.ConnectTimeout)
	setYAMLValue(&c.ExitTimeout, yc.ExitTimeout)
	setYAMLValue(&c.ReadHeaderTimeout, yc.ReadHeaderTimeout)
	setYAMLValue(&c.ReadTimeout, yc.ReadTimeout)
	setYAMLValue(&c.WriteTimeout, yc.WriteTimeout)
	setYAMLValue(&c.TransportMaxIdleConns, yc.TransportMaxIdleConns)
	setYAMLValue(&c.TransportMaxIdleConnsPerHost, yc.TransportMaxIdleConnsPerHost)
	setYAMLValue(&c.SupportProxyProtocol, yc.SupportProxyProtocol)
	setYAMLValue(&c.StatsSocketDir, yc.StatsSocketDir)
	setYAMLValue(&c.AllowMissingRole, yc.AllowMissingRole)
	setYAMLValue(&c.AdditionalErrorMessageOnDeny, yc.DenyMessageExtra)
	setYAMLValue(&c.TimeConnect, yc.TimeConnect)
	setYAMLValue(&c.UnsafeAllowPrivateRanges, yc.UnsafeAllowPrivateRanges)
	setYAMLValue(&c.MaxConcurrentConnectTunnels, yc.MaxConcurrentConnectTunnels)
	setYAMLValue(&c.DNSTimeout, yc.DNSTimeout)
}

func (c *Config) applyYAMLRules(yc yamlConfig) error {
	for _, rules := range []struct {
		ranges, addresses []string
		destination       *[]RuleRange
	}{
		{yc.DenyRanges, yc.DenyAddresses, &c.DenyRanges},
		{yc.AllowRanges, yc.AllowAddresses, &c.AllowRanges},
	} {
		if rules.ranges == nil && rules.addresses == nil {
			continue
		}
		ranges, err := parseRanges(rules.ranges)
		if err != nil {
			return err
		}
		addresses, err := parseAddresses(rules.addresses)
		if err != nil {
			return err
		}
		*rules.destination = append(ranges, addresses...)
	}
	return nil
}

func (c *Config) applyYAMLRateLimits(yc yamlConfig) error {
	if yc.MaxConcurrentRequests == nil && yc.MaxRequestRate == nil && yc.MaxRequestBurst == nil {
		return nil
	}
	concurrent, rate, burst := c.MaxConcurrentRequests, c.MaxRequestRate, c.MaxRequestBurst
	if burst == 0 && yc.MaxRequestBurst == nil {
		burst = DefaultMaxRequestBurst
	}
	setYAMLValue(&concurrent, yc.MaxConcurrentRequests)
	setYAMLValue(&rate, yc.MaxRequestRate)
	setYAMLValue(&burst, yc.MaxRequestBurst)
	return c.SetRateLimits(concurrent, rate, burst)
}

// LoadConfig loads a file starting with NewConfig defaults.
func LoadConfig(filePath string) (*Config, error) {
	config := NewConfig()
	if err := config.LoadFile(filePath); err != nil {
		return nil, err
	}
	return config, nil
}

// LoadFile applies settings present in the YAML file, retaining omitted settings
// (including security flags) and injected dependencies. Either allow-list key
// replaces the combined allow rules; either deny-list key replaces the combined
// deny rules. An explicit empty list clears those rules. The SetAllow/SetDeny
// methods still append, so call them after LoadFile to extend the file's rules.
// Start with NewConfig for defaults and set Log before loading diagnostics.
func (c *Config) LoadFile(filePath string) error {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return yaml.UnmarshalStrict(bytes, c)
}

func (c *Config) applyYAMLTLS(config *yamlConfigTls) error {
	if config != nil {
		if config.CertFile == "" {
			return errors.New("'tls' section requires 'cert_file'")
		}

		key_file := config.KeyFile
		if key_file == "" {
			// Assume CertFile is a cert+key bundle
			key_file = config.CertFile
		}

		err := c.SetupTls(config.CertFile, key_file, config.ClientCAFiles)
		if err != nil {
			return err
		}

		err = c.SetupCrls(config.CRLFiles)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) applyYAMLMITM(certFile, keyFile string) error {
	if certFile != "" || keyFile != "" {
		if certFile == "" {
			return errors.New("mitm_ca_cert_file required when mitm_ca_key_file is set")
		}
		if keyFile == "" {
			return errors.New("mitm_ca_key_file required when mitm_ca_cert_file is set")
		}
		mitmCa, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("mitm_ca_key_file error tls.LoadX509KeyPair: %w", err)
		}
		// set the leaf certificat to reduce per-handshake processing
		if len(mitmCa.Certificate) == 0 {
			return errors.New("mitm_ca_key_file error: mitm_ca_key_file contains no certificates")
		}
		if mitmCa.Leaf, err = x509.ParseCertificate(mitmCa.Certificate[0]); err != nil {
			return fmt.Errorf("could not populate x509 Leaf value: %w", err)
		}
		c.MitmTLSConfig = goproxy.TLSConfigFromCA(&mitmCa)
	}

	return nil
}
