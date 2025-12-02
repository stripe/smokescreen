package smokescreen

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
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

// Port and ExitTimeout use a pointer so we can distinguish unset vs explicit
// zero, to avoid overriding a non-zero default when the value is not set.
type yamlConfig struct {
	Ip                   string
	Port                 *uint16
	DenyRanges           []string `yaml:"deny_ranges"`
	AllowRanges          []string `yaml:"allow_ranges"`
	DenyAddresses        []string `yaml:"deny_addresses"`
	AllowAddresses       []string `yaml:"allow_addresses"`
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

	// HTTP server timeouts to prevent DoS attacks
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`

	StatsSocketDir      string `yaml:"stats_socket_dir"`
	StatsSocketFileMode string `yaml:"stats_socket_file_mode"`

	TransportMaxIdleConns        int `yaml:"transport_max_idle_conns"`
	TransportMaxIdleConnsPerHost int `yaml:"transport_max_idle_conns_per_host"`

	TimeConnect bool `yaml:"time_connect"`

	Tls *yamlConfigTls
	// Currently not configurable via YAML: RoleFromRequest, Log, DisabledAclPolicyActions

	UnsafeAllowPrivateRanges bool   `yaml:"unsafe_allow_private_ranges"`
	MitmCaCertFile           string `yaml:"mitm_ca_cert_file"`
	MitmCaKeyFile            string `yaml:"mitm_ca_key_file"`

	// Rate and concurrency limiting
	MaxConcurrentRequests int     `yaml:"max_concurrent_requests"`
	MaxRequestRate        float64 `yaml:"max_request_rate"`
	MaxRequestBurst       int     `yaml:"max_request_burst"`

	DNSTimeout            time.Duration `yaml:"dns_timeout"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yc yamlConfig
	*c = *NewConfig()

	err := unmarshal(&yc)
	if err != nil {
		return err
	}

	c.Ip = yc.Ip

	if yc.Port != nil {
		c.Port = *yc.Port
	}

	err = c.SetDenyRanges(yc.DenyRanges)
	if err != nil {
		return err
	}

	err = c.SetAllowRanges(yc.AllowRanges)
	if err != nil {
		return err
	}

	err = c.SetDenyAddresses(yc.DenyAddresses)
	if err != nil {
		return err
	}

	err = c.SetAllowAddresses(yc.AllowAddresses)
	if err != nil {
		return err
	}

	err = c.SetResolverAddresses(yc.Resolvers)
	if err != nil {
		return err
	}

	c.IdleTimeout = yc.IdleTimeout
	c.ConnectTimeout = yc.ConnectTimeout
	if yc.ExitTimeout != nil {
		c.ExitTimeout = *yc.ExitTimeout
	}

	c.TransportMaxIdleConns = yc.TransportMaxIdleConns
	c.TransportMaxIdleConnsPerHost = yc.TransportMaxIdleConnsPerHost

	// Apply HTTP server timeouts if configured, otherwise keep defaults
	if yc.ReadHeaderTimeout != 0 {
		c.ReadHeaderTimeout = yc.ReadHeaderTimeout
	}
	if yc.ReadTimeout != 0 {
		c.ReadTimeout = yc.ReadTimeout
	}
	if yc.WriteTimeout != 0 {
		c.WriteTimeout = yc.WriteTimeout
	}

	err = c.SetupStatsd(yc.StatsdAddress)
	if err != nil {
		return err
	}

	if yc.EgressAclFile != "" {
		err = c.SetupEgressAcl(yc.EgressAclFile)
		if err != nil {
			return err
		}
	}

	c.SupportProxyProtocol = yc.SupportProxyProtocol

	if yc.StatsSocketDir != "" {
		c.StatsSocketDir = yc.StatsSocketDir
	}

	if yc.StatsSocketFileMode != "" {
		filemode, err := strconv.ParseInt(yc.StatsSocketFileMode, 8, 9)

		if err != nil {
			c.Log.Fatal(err)
		}

		c.StatsSocketFileMode = os.FileMode(filemode)
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

		err = c.SetupTls(yc.Tls.CertFile, key_file, yc.Tls.ClientCAFiles)
		if err != nil {
			return err
		}

		err = c.SetupCrls(yc.Tls.CRLFiles)
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
		c.Network = yc.Network
	}

	c.AllowMissingRole = yc.AllowMissingRole
	c.AdditionalErrorMessageOnDeny = yc.DenyMessageExtra
	c.TimeConnect = yc.TimeConnect
	c.UnsafeAllowPrivateRanges = yc.UnsafeAllowPrivateRanges

	if yc.MitmCaCertFile != "" || yc.MitmCaKeyFile != "" {
		if yc.MitmCaCertFile == "" {
			return errors.New("mitm_ca_cert_file required when mitm_ca_key_file is set")
		}
		if yc.MitmCaKeyFile == "" {
			return errors.New("mitm_ca_key_file required when mitm_ca_cert_file is set")
		}
		mitmCa, err := tls.LoadX509KeyPair(yc.MitmCaCertFile, yc.MitmCaKeyFile)
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

	// Set rate and concurrency limits
	if yc.MaxConcurrentRequests > 0 || yc.MaxRequestRate > 0 {
		MaxRequestBurst := 0
		if yc.MaxRequestBurst > 0 {
			MaxRequestBurst = yc.MaxRequestBurst
		}
		if err := c.SetRateLimits(yc.MaxConcurrentRequests, yc.MaxRequestRate, MaxRequestBurst); err != nil {
			return err
		}
	}

	if yc.DNSTimeout > 0 {
		c.DNSTimeout = yc.DNSTimeout
	}

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
