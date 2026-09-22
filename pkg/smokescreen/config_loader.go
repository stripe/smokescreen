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
	"github.com/stripe/smokescreen/internal/logging"
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

	ConnectTimeout *time.Duration `yaml:"connect_timeout"`
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
	MaxRequestBurst       *int    `yaml:"max_request_burst"`

	// Tunnel limiting (for long-lived CONNECT connections)
	MaxConcurrentConnectTunnels int `yaml:"max_concurrent_connect_tunnels"`

	DNSTimeout time.Duration `yaml:"dns_timeout"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yc yamlConfig
	hadMetrics := c.MetricsClient != nil
	c.resetForYAML()

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
	if yc.ConnectTimeout != nil {
		c.ConnectTimeout = *yc.ConnectTimeout
	}
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

	if yc.StatsdAddress != "" || !hadMetrics {
		if err := c.SetupStatsd(yc.StatsdAddress); err != nil {
			return err
		}
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
			c.Log.Error(logging.Sanitize(fmt.Sprint(err)))
			os.Exit(1)
		}

		c.StatsSocketFileMode = os.FileMode(filemode)
	}

	if err := c.applyYAMLTLS(yc.Tls); err != nil {
		return err
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

	if err := c.applyYAMLMITM(yc.MitmCaCertFile, yc.MitmCaKeyFile); err != nil {
		return err
	}

	// Set rate and concurrency limits
	if yc.MaxConcurrentRequests > 0 || yc.MaxRequestRate > 0 {
		maxBurst := DefaultMaxRequestBurst
		if yc.MaxRequestBurst != nil {
			maxBurst = *yc.MaxRequestBurst
		}
		if err := c.SetRateLimits(yc.MaxConcurrentRequests, yc.MaxRequestRate, maxBurst); err != nil {
			return err
		}
	}

	// Set tunnel limit for CONNECT connections
	if yc.MaxConcurrentConnectTunnels > 0 {
		c.MaxConcurrentConnectTunnels = yc.MaxConcurrentConnectTunnels
	}

	if yc.DNSTimeout > 0 {
		c.DNSTimeout = yc.DNSTimeout
	}

	return nil
}

// LoadConfig loads a file using an instance-local default logger.
func LoadConfig(filePath string) (*Config, error) {
	config := NewConfig()
	if err := config.LoadFile(filePath); err != nil {
		return nil, err
	}
	return config, nil
}

// LoadFile applies YAML configuration, preserving injected dependencies unless
// explicitly configured by the file. Set Log before calling to capture loading diagnostics.
func (c *Config) LoadFile(filePath string) error {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return yaml.UnmarshalStrict(bytes, c)
}

// resetForYAML resets file-configurable values while keeping caller-owned dependencies.
func (c *Config) resetForYAML() {
	previous := *c
	*c = *NewConfig()
	c.Log = logging.OrDefault(previous.Log)
	if previous.Resolver != nil {
		c.Resolver = previous.Resolver
	}
	if previous.MetricsClient != nil {
		c.MetricsClient = previous.MetricsClient
	}
	c.EgressACL = previous.EgressACL
	c.ConnTracker = previous.ConnTracker
	c.Listener = previous.Listener
	c.TlsConfig = previous.TlsConfig
	if previous.TlsConfig != nil {
		c.CrlByAuthorityKeyId = previous.CrlByAuthorityKeyId
		c.revokedCertSerials = previous.revokedCertSerials
		c.clientCasBySubjectKeyId = previous.clientCasBySubjectKeyId
	}
	c.Healthcheck = previous.Healthcheck
	c.RoleFromRequest = previous.RoleFromRequest
	c.DisabledAclPolicyActions = previous.DisabledAclPolicyActions
	c.ProxyDialTimeout = previous.ProxyDialTimeout
	c.RejectResponseHandler = previous.RejectResponseHandler
	c.RejectResponseHandlerWithCtx = previous.RejectResponseHandlerWithCtx
	c.AcceptResponseHandler = previous.AcceptResponseHandler
	c.PostDecisionRequestHandler = previous.PostDecisionRequestHandler
	c.MitmTLSConfig = previous.MitmTLSConfig
	c.UpstreamProxySelector = previous.UpstreamProxySelector
	c.UpstreamProxyTLSConfigHandler = previous.UpstreamProxyTLSConfigHandler
	c.UpstreamProxyConnectReqHandler = previous.UpstreamProxyConnectReqHandler

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
