package smokescreen

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stripe/goproxy"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

// Configuration defaults
const (
	// Server defaults
	DefaultPort              uint16        = 4750
	DefaultConnectTimeout                  = 10 * time.Second
	DefaultExitTimeout                     = 500 * time.Minute
	DefaultNetwork             = "ip"
	DefaultStatsSocketFileMode = 0700

	// HTTP server timeouts
	DefaultReadHeaderTimeout = 300 * time.Second
	DefaultReadTimeout       = 300 * time.Second
	DefaultWriteTimeout      = 300 * time.Second

	// DNS
	DefaultDNSTimeout = 5 * time.Second

	// Prometheus defaults
	DefaultPrometheusEndpoint = "/metrics"
	DefaultPrometheusListenIP = "0.0.0.0"
	DefaultPrometheusPort     = "9810"

	// Statsd defaults
	DefaultStatsdAddress = "127.0.0.1:8200"

	// Rate limiting defaults
	DefaultMaxConcurrentRequests = 0    // 0 = unlimited
	DefaultMaxRequestRate        = 0.0  // 0 = unlimited
	DefaultMaxRequestBurst       = -1   // -1 = use 2x rate
)

type RuleRange struct {
	Net  net.IPNet
	Port int
}

// Resolver implements the interface needed by smokescreen and implemented by *net.Resolver
// This will allow different resolvers to also be provided
type Resolver interface {
	LookupPort(ctx context.Context, network, service string) (port int, err error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type Config struct {
	Ip                           string
	Port                         uint16
	Listener                     net.Listener
	DenyRanges                   []RuleRange
	AllowRanges                  []RuleRange
	Resolver                     Resolver
	ConnectTimeout               time.Duration
	ExitTimeout                  time.Duration
	MetricsClient                metrics.MetricsClientInterface
	EgressACL                    acl.Decider
	SupportProxyProtocol         bool
	TlsConfig                    *tls.Config
	CrlByAuthorityKeyId          map[string]*pkix.CertificateList
	RoleFromRequest              func(subject *http.Request) (string, error)
	clientCasBySubjectKeyId      map[string]*x509.Certificate
	AdditionalErrorMessageOnDeny string
	Log                          *log.Logger
	DisabledAclPolicyActions     []string
	AllowMissingRole             bool
	StatsSocketDir               string
	StatsSocketFileMode          os.FileMode
	StatsServer                  *StatsServer // StatsServer
	ConnTracker                  conntrack.TrackerInterface
	Healthcheck                  http.Handler // User defined http.Handler for optional requests to a /healthcheck endpoint
	ShuttingDown                 atomic.Value // Stores a boolean value indicating whether the proxy is actively shutting down

	// Network type to use when performing DNS lookups. Must be one of "ip", "ip4" or "ip6".
	Network string

	// A connection is idle if it has been inactive (no bytes in/out) for this many seconds.
	IdleTimeout time.Duration

	// HTTP server timeouts to prevent DoS attacks
	ReadHeaderTimeout time.Duration // Maximum time to read request headers
	ReadTimeout       time.Duration // Maximum time to read entire request
	WriteTimeout      time.Duration // Maximum time to write response

	// These are *only* used for traditional HTTP proxy requests
	TransportMaxIdleConns        int
	TransportMaxIdleConnsPerHost int

	// These are the http and https address for the upstream proxy
	UpstreamHttpProxyAddr  string
	UpstreamHttpsProxyAddr string

	// Used for logging connection time
	TimeConnect bool

	// Custom Dial Timeout function to be called
	ProxyDialTimeout func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)

	// Custom handler to allow clients to modify reject responses
	// Deprecated: RejectResponseHandler is deprecated.Please use RejectResponseHandlerWithCtx instead.
	RejectResponseHandler func(*http.Response)

	// Custom handler to allow clients to modify reject responses
	// In case RejectResponseHandler is set, this cannot be used.
	RejectResponseHandlerWithCtx func(*SmokescreenContext, *http.Response)

	// Custom handler to allow clients to modify successful CONNECT responses
	AcceptResponseHandler func(*SmokescreenContext, *http.Response) error

	// UnsafeAllowPrivateRanges inverts the default behavior, telling smokescreen to allow private IP
	// ranges by default (exempting loopback and unicast ranges)
	// This setting can be used to configure Smokescreen with a blocklist, rather than an allowlist
	UnsafeAllowPrivateRanges bool

	// TemporarilyDeferredIPs contains a list of IP addresses that should be temporarily
	// deferred during resolution but can be used as fallback if no other IPs are available
	TemporarilyDeferredIPs []string

	// Custom handler for users to allow running code per requests, users can pass in custom methods to verify requests based
	// on headers, code for metrics etc.
	// If smokescreen denies a request, this handler is not called.
	// If the handler returns an error, smokescreen will deny the request.
	PostDecisionRequestHandler func(*http.Request) error
	// MitmCa is used to provide a custom CA for MITM
	MitmTLSConfig func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error)

	// AddServerIpHeader configures goproxy to add X-Server-Ip header to HTTP CONNECT response
	// populated with the remote server IP address
	AddServerIpHeader bool

	// UpstreamProxySelector allows dynamically selecting an upstream proxy for a request.
	// Called after ACL decision and DNS resolution, but before establishing the connection.
	//
	// Return value should be a complete proxy URL (e.g., "https://proxy.example.com:8080")
	// or empty string to fall back to the client-requested proxy (if any) or direct connection.
	//
	// Selection priority: UpstreamProxySelector > client X-Upstream-Https-Proxy header > direct connection
	//
	// IMPORTANT: This function is trusted and returned URLs are NOT validated. Ensure your
	// implementation returns only safe, verified proxy URLs. The function must be thread-safe
	// as it will be called concurrently for multiple requests.
	UpstreamProxySelector func(sctx *SmokescreenContext, decision *ACLDecision) (proxyURL string)

	// MaxConcurrentRequests limits the number of requests that can be processed simultaneously.
	// Set to 0 to disable concurrency limiting.
	MaxConcurrentRequests int

	// MaxRequestRate limits the number of requests per second.
	// Set to 0 to disable rate limiting.
	MaxRequestRate float64

	// MaxRequestBurst is the maximum number of requests allowed in a burst.
	// Set to 0 to use default (2x MaxRequestRate).
	MaxRequestBurst int

	// DNSTimeout is the maximum time to wait for DNS resolution.
	// Set to 0 to use default (5 seconds).
	DNSTimeout time.Duration

	// UpstreamProxyTLSConfigHandler allows customization of TLS config for upstream proxy connections.
	// This is passed through to goproxy's UpstreamProxyTLSConfigHandler.
	//
	// If this handler returns an error, the connection is closed and the error is returned to the client.
	// The function must be thread-safe as it will be called concurrently for multiple requests.
	UpstreamProxyTLSConfigHandler func(ctx *goproxy.ProxyCtx, baseConfig *tls.Config, proxyURL *url.URL) (*tls.Config, error)

	// UpstreamProxyConnectReqHandler allows modification of CONNECT request to upstream proxy.
	// This is passed through to goproxy's UpstreamProxyConnectReqHandler.
	//
	// If this handler returns an error, the connection is closed and the error is returned to the client.
	// The function must be thread-safe as it will be called concurrently for multiple requests.
	UpstreamProxyConnectReqHandler func(ctx *goproxy.ProxyCtx, req *http.Request) error

	// Self-connection detection field to prevent recursive proxy attacks
	// LocalIPs contains all IP addresses assigned to network interfaces on this host
	LocalIPs []net.IP
}

type missingRoleError struct {
	error
}

func MissingRoleError(s string) error {
	return missingRoleError{errors.New(s)}
}

func IsMissingRoleError(err error) bool {
	_, ok := err.(missingRoleError)
	return ok
}

func parseRanges(rangeStrings []string) ([]RuleRange, error) {
	outRanges := make([]RuleRange, len(rangeStrings))
	for i, str := range rangeStrings {
		_, ipnet, err := net.ParseCIDR(str)
		if err != nil {
			return outRanges, err
		}
		outRanges[i].Net = *ipnet
	}
	return outRanges, nil
}

func parseAddresses(addressStrings []string) ([]RuleRange, error) {
	outRanges := make([]RuleRange, len(addressStrings))
	for i, str := range addressStrings {
		ip := net.ParseIP(str)
		if ip == nil {
			ipStr, portStr, err := net.SplitHostPort(str)
			if err != nil {
				return outRanges, fmt.Errorf("address must be in the form ip[:port], got %s", str)
			}

			ip = net.ParseIP(ipStr)
			if ip == nil {
				return outRanges, fmt.Errorf("invalid IP address '%s'", ipStr)
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				return outRanges, fmt.Errorf("invalid port number '%s'", portStr)
			}

			outRanges[i].Port = port
		}

		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}

		outRanges[i].Net = net.IPNet{
			IP:   ip,
			Mask: mask,
		}
	}
	return outRanges, nil
}

func (config *Config) SetDenyRanges(rangeStrings []string) error {
	var err error
	ranges, err := parseRanges(rangeStrings)
	if err != nil {
		return err
	}
	config.DenyRanges = append(config.DenyRanges, ranges...)
	return nil
}

func (config *Config) SetAllowRanges(rangeStrings []string) error {
	var err error
	ranges, err := parseRanges(rangeStrings)
	if err != nil {
		return err
	}
	config.AllowRanges = append(config.AllowRanges, ranges...)
	return nil
}

func (config *Config) SetDenyAddresses(addressStrings []string) error {
	var err error
	ranges, err := parseAddresses(addressStrings)
	if err != nil {
		return err
	}
	config.DenyRanges = append(config.DenyRanges, ranges...)
	return nil
}

func (config *Config) SetAllowAddresses(addressStrings []string) error {
	var err error
	ranges, err := parseAddresses(addressStrings)
	if err != nil {
		return err
	}
	config.AllowRanges = append(config.AllowRanges, ranges...)
	return nil
}

func (config *Config) SetResolverAddresses(resolverAddresses []string) error {
	// TODO: support round-robin between multiple addresses
	if len(resolverAddresses) > 1 {
		return fmt.Errorf("only one resolver address allowed, %d provided", len(resolverAddresses))
	}

	// No resolver specified, use the system resolver
	if len(resolverAddresses) == 0 {
		return nil
	}

	addr := resolverAddresses[0]
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	r := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", addr)
		},
	}
	config.Resolver = &r
	return nil
}

// SetRateLimits configures the rate and concurrency limits for the proxy.
// maxConcurrent limits simultaneous requests (0 = unlimited).
// maxRate limits requests per second (0 = unlimited).
// maxRequestBurst: -1 = use default (2x rate), >=0 = must be greater than maxRate.
func (config *Config) SetRateLimits(maxConcurrent int, maxRate float64, maxRequestBurst int) error {
	if maxConcurrent < 0 {
		return fmt.Errorf("maxConcurrent must be >= 0, got %d", maxConcurrent)
	}
	if maxRate < 0 {
		return fmt.Errorf("maxRate must be >= 0, got %.2f", maxRate)
	}
	
	if maxRequestBurst >= 0 && maxRate > 0 && float64(maxRequestBurst) <= maxRate {
		return fmt.Errorf("maxRequestBurst (%d) must be greater than maxRequestRate (%.2f); omit to use default (2x rate)", maxRequestBurst, maxRate)
	}
	
	// Apply default: 2x rate when not explicitly configured or configured negative
	if maxRequestBurst < 0 {
		maxRequestBurst = int(maxRate * 2)
	}
	
	config.MaxConcurrentRequests = maxConcurrent
	config.MaxRequestRate = maxRate
	config.MaxRequestBurst = maxRequestBurst
	return nil
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

func NewConfig() *Config {
	log.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	return &Config{
		Resolver:                &net.Resolver{},
		CrlByAuthorityKeyId:     make(map[string]*pkix.CertificateList),
		clientCasBySubjectKeyId: make(map[string]*x509.Certificate),
		Log:                     log.New(),
		Port:                    DefaultPort,
		ExitTimeout:             DefaultExitTimeout,
		StatsSocketFileMode:     os.FileMode(DefaultStatsSocketFileMode),
		ShuttingDown:            atomic.Value{},
		MetricsClient:           metrics.NewNoOpMetricsClient(),
		Network:                 DefaultNetwork,
		// Set secure defaults to prevent DoS attacks
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		DNSTimeout:        DefaultDNSTimeout,
	}
}

// Gathers all local IP addresses to prevent recursive proxy attacks.
func (config *Config) InitializeSelfConnectionDetection() error {
	localIPs, err := getAllLocalIPs()
	if err != nil {
		return fmt.Errorf("failed to get local IPs for self-connection detection: %w", err)
	}
	config.LocalIPs = localIPs

	ipStrings := make([]string, len(config.LocalIPs))
	for i, ip := range config.LocalIPs {
		ipStrings[i] = ip.String()
	}
	config.Log.WithFields(log.Fields{
		"listening_ip":   config.Ip,
		"listening_port": config.Port,
		"local_ips":      ipStrings,
	}).Info("Self-connection detection initialized")

	return nil
}

// getAllLocalIPs returns all IP addresses assigned to network interfaces on this host.
// This includes loopback, private, public, and any other IPs.
func getAllLocalIPs() ([]net.IP, error) {
	var localIPs []net.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			localIPs = append(localIPs, ip)
		}
	}

	return localIPs, nil
}

func (config *Config) SetupCrls(crlFiles []string) error {
	for _, crlFile := range crlFiles {
		crlBytes, err := ioutil.ReadFile(crlFile)
		if err != nil {
			return err
		}

		certList, err := x509.ParseCRL(crlBytes)
		if err != nil {
			log.Printf("Failed to parse CRL in '%s': %#v\n", crlFile, err)
		}

		// find the X509v3 Authority Key Identifier in the extensions (2.5.29.35)
		crlIssuerId := ""
		extensionOid := []int{2, 5, 29, 35}
		for _, v := range certList.TBSCertList.Extensions {
			if v.Id.Equal(extensionOid) { // Hurray, we found it
				// Boo, it's ASN.1.
				var crlAuthorityKey authKeyId
				_, err := asn1.Unmarshal(v.Value, &crlAuthorityKey)
				if err != nil {
					fmt.Printf("error: Failed to read AuthorityKey: %#v\n", err)
					continue
				}
				crlIssuerId = string(crlAuthorityKey.Id)
				break
			}
		}
		if crlIssuerId == "" {
			log.Print(fmt.Errorf("error: CRL from '%s' has no Authority Key Identifier: ignoring it\n", crlFile))
			continue
		}

		// Make sure we have a CA for this CRL or warn
		caCert, ok := config.clientCasBySubjectKeyId[crlIssuerId]

		if !ok {
			log.Printf("warn: CRL loaded for issuer '%s' but no such CA loaded: ignoring it\n", hex.EncodeToString([]byte(crlIssuerId)))
			fmt.Printf("%#v loaded certs\n", len(config.clientCasBySubjectKeyId))
			continue
		}

		// At this point, we have the CA certificate and the CRL. All that's left before evicting the CRL we currently trust is to verify the new CRL's signature
		err = caCert.CheckCRLSignature(certList)
		if err != nil {
			fmt.Printf("error: Could not trust CRL. Error during signature check: %#v\n", err)
			continue
		}

		// At this point, we have a new CRL which we trust. Let's evict the old one.
		config.CrlByAuthorityKeyId[crlIssuerId] = certList
		fmt.Printf("info: Loaded CRL for Authority ID '%s'\n", hex.EncodeToString([]byte(crlIssuerId)))
	}

	// Verify that all CAs loaded have a CRL
	for k := range config.clientCasBySubjectKeyId {
		_, ok := config.CrlByAuthorityKeyId[k]
		if !ok {
			fmt.Printf("warn: no CRL loaded for Authority ID '%s'\n", hex.EncodeToString([]byte(k)))
		}
	}
	return nil
}

func (config *Config) SetupStatsdWithNamespace(addr, namespace string) error {
	if addr == "" {
		fmt.Println("warn: no statsd addr provided, using noop client")
		config.MetricsClient = metrics.NewNoOpMetricsClient()
		return nil
	}

	mc, err := metrics.NewStatsdMetricsClient(addr, namespace)
	if err != nil {
		return err
	}
	config.MetricsClient = mc
	return nil
}

func (config *Config) SetupStatsd(addr string) error {
	return config.SetupStatsdWithNamespace(addr, DefaultStatsdNamespace)
}

func (config *Config) SetupPrometheus(endpoint string, port string, listenAddr string) error {
	metricsClient, err := metrics.NewPrometheusMetricsClient(endpoint, port, listenAddr)
	if err != nil {
		return err
	}
	config.MetricsClient = metricsClient
	return nil
}

func (config *Config) SetupEgressAcl(aclFile string) error {
	if aclFile == "" {
		config.EgressACL = nil
		return nil
	}

	log.Printf("Loading egress ACL from %s", aclFile)

	egressACL, err := acl.New(config.Log, acl.NewYAMLLoader(aclFile), config.DisabledAclPolicyActions)
	if err != nil {
		log.Print(err)
		return err
	}
	config.EgressACL = egressACL

	return nil
}

func addCertsFromFile(config *Config, pool *x509.CertPool, fileName string) error {
	data, err := ioutil.ReadFile(fileName)

	//TODO this is a bit awkward
	config.populateClientCaMap(data)

	if err != nil {
		return err
	}
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return fmt.Errorf("Failed to load any certificates from file '%s'", fileName)
	}
	return nil
}

// certFile and keyFile may be the same file containing concatenated PEM blocks
func (config *Config) SetupTls(certFile, keyFile string, clientCAFiles []string) error {
	if certFile == "" || keyFile == "" {
		return errors.New("both certificate and key files must be specified to set up TLS")
	}

	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	clientAuth := tls.NoClientCert
	clientCAs := x509.NewCertPool()

	if len(clientCAFiles) != 0 {
		clientAuth = tls.VerifyClientCertIfGiven
		for _, caFile := range clientCAFiles {
			err = addCertsFromFile(config, clientCAs, caFile)
			if err != nil {
				return err
			}
		}
	}

	config.TlsConfig = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}

	return nil
}

func (config *Config) Validate() error {
	if config.RejectResponseHandler != nil && config.RejectResponseHandlerWithCtx != nil {
		return errors.New("RejectResponseHandler and RejectResponseHandlerWithCtx cannot be used together")
	}
	return nil
}

func (config *Config) populateClientCaMap(pemCerts []byte) (ok bool) {

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		fmt.Printf("info: Loaded CA with Authority ID '%s'\n", hex.EncodeToString(cert.SubjectKeyId))
		config.clientCasBySubjectKeyId[string(cert.SubjectKeyId)] = cert
		ok = true
	}
	return
}
