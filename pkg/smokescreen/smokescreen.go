package smokescreen

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/internal/einhorn"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/hostport"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

const (
	ipAllowDefault ipType = iota
	ipAllowUserConfigured
	ipDenyNotGlobalUnicast
	ipDenyPrivateRange
	ipDenyUserConfigured
	ipDenyCGNAT

	denyMsgTmpl = "Egress proxying is denied to host '%s': %s."

	httpProxy    = "http"
	connectProxy = "connect"
)

const (
	LogFieldID               = "id"
	LogFieldOutLocalAddr     = "outbound_local_addr"
	LogFieldOutRemoteAddr    = "outbound_remote_addr"
	LogFieldInRemoteAddr     = "inbound_remote_addr"
	LogFieldProxyType        = "proxy_type"
	LogFieldRequestedHost    = "requested_host"
	LogFieldStartTime        = "start_time"
	LogFieldTraceID          = "trace_id"
	LogFieldInRemoteX509CN   = "inbound_remote_x509_cn"
	LogFieldInRemoteX509OU   = "inbound_remote_x509_ou"
	LogFieldRole             = "role"
	LogFieldProject          = "project"
	LogFieldContentLength    = "content_length"
	LogFieldDecisionReason   = "decision_reason"
	LogFieldEnforceWouldDeny = "enforce_would_deny"
	LogFieldAllow            = "allow"
	LogFieldError            = "error"
	CanonicalProxyDecision   = "CANONICAL-PROXY-DECISION"
	LogFieldConnEstablishMS  = "conn_establish_time_ms"
	LogFieldDNSLookupTime    = "dns_lookup_time_ms"
	LogMitmReqUrl            = "mitm_req_url"
	LogMitmReqMethod         = "mitm_req_method"
	LogMitmReqHeaders        = "mitm_req_headers"
)

type ipType int

type ACLDecision struct {
	Reason, Role, Project, OutboundHost string
	ResolvedAddr                        *net.TCPAddr
	allow                               bool
	enforceWouldDeny                    bool
	MitmConfig                          *acl.MitmConfig
	SelectedUpstreamProxy               string // The proxy that will be used (from selector or client)
	ClientRequestedProxy                string // The proxy requested by the client via X-Upstream-Https-Proxy header
}

type SmokescreenContext struct {
	cfg           *Config
	start         time.Time
	Decision      *ACLDecision
	ProxyType     string
	Logger        *logrus.Entry
	RequestedHost string

	// Time spent resolving the requested hostname
	lookupTime time.Duration
}

// ExitStatus is used to log Smokescreen's connection status at shutdown time
type ExitStatus int

const (
	Closed ExitStatus = iota
	Idle
	Timeout
)

func (e ExitStatus) String() string {
	switch e {
	case Closed:
		return "All connections closed"
	case Idle:
		return "All connections idle"
	case Timeout:
		return "Timed out waiting for connections to become idle"
	default:
		return "Unknown exit status"
	}
}

type denyError struct {
	error
}

func (t ipType) IsAllowed() bool {
	return t == ipAllowDefault || t == ipAllowUserConfigured
}

func (t ipType) String() string {
	switch t {
	case ipAllowDefault:
		return "Allow: Default"
	case ipAllowUserConfigured:
		return "Allow: User Configured"
	case ipDenyNotGlobalUnicast:
		return "Deny: Not Global Unicast"
	case ipDenyPrivateRange:
		return "Deny: Private Range"
	case ipDenyUserConfigured:
		return "Deny: User Configured"
	case ipDenyCGNAT:
		return "Deny: CGNAT Range"
	default:
		panic(fmt.Errorf("unknown ip type %d", t))
	}
}

func (t ipType) statsdString() string {
	switch t {
	case ipAllowDefault:
		return "resolver.allow.default"
	case ipAllowUserConfigured:
		return "resolver.allow.user_configured"
	case ipDenyNotGlobalUnicast:
		return "resolver.deny.not_global_unicast"
	case ipDenyPrivateRange:
		return "resolver.deny.private_range"
	case ipDenyUserConfigured:
		return "resolver.deny.user_configured"
	case ipDenyCGNAT:
		return "resolver.deny.cgnat_range"
	default:
		panic(fmt.Errorf("unknown ip type %d", t))
	}
}

const errorHeader = "X-Smokescreen-Error"
const roleHeader = "X-Smokescreen-Role"
const traceHeader = "X-Smokescreen-Trace-ID"

func addrIsInRuleRange(ranges []RuleRange, addr *net.TCPAddr) bool {
	for _, rng := range ranges {
		// If the range specifies a port and the port doesn't match,
		// then this range doesn't match
		if rng.Port != 0 && addr.Port != rng.Port {
			continue
		}

		if rng.Net.Contains(addr.IP) {
			return true
		}
	}
	return false
}

var cgnatRange *net.IPNet

func init() {
	var err error
	// RFC 6598 CGNAT range
	_, cgnatRange, err = net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(fmt.Sprintf("smokescreen internal error: could not parse CGNAT range: %v", err))
	}
}

// addrIsCGNAT checks if an address is within the Carrier-Grade NAT range.
func addrIsCGNAT(addr *net.TCPAddr) bool {
	return cgnatRange.Contains(addr.IP)
}

func addrIsTemporarilyDeferred(temporarilyDeferredIPs []string, addr *net.TCPAddr) bool {
	for _, ipRange := range temporarilyDeferredIPs {
		if ip := net.ParseIP(ipRange); ip != nil {
			if addr.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func classifyAddr(config *Config, addr *net.TCPAddr) ipType {
	if !addr.IP.IsGlobalUnicast() || addr.IP.IsLoopback() {
		if addrIsInRuleRange(config.AllowRanges, addr) {
			return ipAllowUserConfigured
		} else {
			return ipDenyNotGlobalUnicast
		}
	}

	if addrIsInRuleRange(config.AllowRanges, addr) {
		return ipAllowUserConfigured
	} else if addrIsInRuleRange(config.DenyRanges, addr) {
		return ipDenyUserConfigured
	} else if addr.IP.IsPrivate() && !config.UnsafeAllowPrivateRanges {
		return ipDenyPrivateRange
	} else if addrIsCGNAT(addr) {
		return ipDenyCGNAT
	} else {
		return ipAllowDefault
	}
}

func resolveTCPAddr(config *Config, network, addr string) (*net.TCPAddr, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unknown network type %q", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resolvedPort, err := config.Resolver.LookupPort(ctx, network, port)
	if err != nil {
		return nil, err
	}

	ips, err := config.Resolver.LookupIP(ctx, config.Network, host)
	if err != nil {
		return nil, err
	}
	if len(ips) < 1 {
		return nil, fmt.Errorf("no IPs resolved")
	}

	// Select the best IP using prioritization logic
	selectedAddr, err := selectTargetAddr(config, ips, resolvedPort)
	if err != nil {
		return nil, err
	}
	return selectedAddr, nil
}

// logFallbackIP logs when a deferred IP is selected as fallback
func logFallbackIP(config *Config, addr *net.TCPAddr) {
	config.Log.WithFields(logrus.Fields{
		"ip":     addr.IP.String(),
		"port":   addr.Port,
		"reason": "all lookup IPs are in deferred list",
	}).Info("Using temporarily deferred IP as fallback")
}

// selectFallbackAddr attempts to select a fallback address from temporarily deferred IPs
//
// Input Expectations:
// - config: Must contain a valid TemporarilyDeferredIPs list (can be empty)
// - fallbackTargets: Pre-filtered list of *net.TCPAddr that are:
//   - ACL-allowed addresses
//   - Present in the TemporarilyDeferredIPs configuration
//   - Collected during the first pass of IP selection
//
// It prioritizes IPs in the order they appear in config.TemporarilyDeferredIPs
// Returns the first matching address found, or nil if no fallback is available
func selectFallbackAddr(config *Config, fallbackTargets []*net.TCPAddr) *net.TCPAddr {
	for _, ipString := range config.TemporarilyDeferredIPs {
		for _, addr := range fallbackTargets {
			parsedIP := net.ParseIP(ipString)
			if parsedIP != nil && addr.IP.Equal(parsedIP) {
				logFallbackIP(config, addr)
				return addr
			}
		}
	}
	return nil
}

// selectTargetAddr chooses the best target address from a list of resolved IPs.
// It prioritizes addresses that are allowed by ACL rules and not in the temporarily deferred list.
// If no preferred addresses are available, it falls back to temporarily deferred addresses.
// Returns an error if no valid addresses are found.
func selectTargetAddr(config *Config, ips []net.IP, port int) (*net.TCPAddr, error) {
	var fallbackTargets []*net.TCPAddr
	var denialReasons []string

	// First pass: look for preferred IPs (allowed and not temporarily deferred)
	for _, ip := range ips {
		targetAddr := &net.TCPAddr{
			IP:   ip,
			Port: port,
		}

		classification := classifyAddr(config, targetAddr)
		if classification.IsAllowed() {
			if len(config.TemporarilyDeferredIPs) > 0 && addrIsTemporarilyDeferred(config.TemporarilyDeferredIPs, targetAddr) {
				// IP is allowed but temporarily deferred, save for fallback
				config.Log.WithFields(logrus.Fields{
					"ip":     targetAddr.IP.String(),
					"port":   targetAddr.Port,
					"reason": "IP is temporarily deny-listed",
				}).Info("Temporarily denying IP, will be used as fallback")
				fallbackTargets = append(fallbackTargets, targetAddr)
				continue
			}
			// IP is allowed and preferred, use it immediately
			return targetAddr, nil
		} else {
			denialReasons = append(denialReasons, fmt.Sprintf("%s denied by rule '%s'", ip.String(), classification))
		}
	}

	// Second pass: if no preferred IPs found, try to use a fallback target
	if len(fallbackTargets) > 0 {
		if fallbackAddr := selectFallbackAddr(config, fallbackTargets); fallbackAddr != nil {
			return fallbackAddr, nil
		}
	}

	// If no IP passes validation, return denyError with details about denials
	if len(denialReasons) > 0 {
		return nil, denyError{fmt.Errorf("no valid IP found among resolved addresses - %s", denialReasons[0])}
	}

	return nil, fmt.Errorf("no IP addresses to evaluate")
}

func safeResolve(config *Config, network, addr string) (*net.TCPAddr, string, error) {
	config.MetricsClient.Incr("resolver.attempts_total", 1)

	resolveStart := time.Now()
	resolved, err := resolveTCPAddr(config, network, addr)
	resolveDuration := time.Since(resolveStart)
	if err != nil {
		config.MetricsClient.Incr("resolver.errors_total", 1)
		return nil, "", err
	}
	config.MetricsClient.Timing("resolver.lookup_time", resolveDuration, 0.5)

	// The classification is already done in resolveTCPAddr, so we just need to log it
	classification := classifyAddr(config, resolved)
	config.MetricsClient.Incr(classification.statsdString(), 1)

	return resolved, classification.String(), nil
}

func proxyContext(ctx context.Context) (*goproxy.ProxyCtx, bool) {
	pctx, ok := ctx.Value(goproxy.ProxyContextKey).(*goproxy.ProxyCtx)
	return pctx, ok
}

func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	pctx, ok := proxyContext(ctx)
	if !ok {
		return nil, fmt.Errorf("dialContext missing required *goproxy.ProxyCtx")
	}

	sctx, ok := pctx.UserData.(*SmokescreenContext)
	if !ok {
		return nil, fmt.Errorf("dialContext missing required *SmokescreenContext")
	}
	d := sctx.Decision

	// If an address hasn't been resolved, does not match the original OutboundHost,
	// or is not tcp we must re-resolve it before establishing the connection.
	if d.ResolvedAddr == nil || d.OutboundHost != addr || network != "tcp" {
		var err error
		d.ResolvedAddr, d.Reason, err = safeResolve(sctx.cfg, network, addr)
		if err != nil {
			if _, ok := err.(denyError); ok {
				sctx.cfg.Log.WithFields(
					logrus.Fields{
						"address": addr,
						"error":   err,
					}).Error("unexpected illegal address in dialer")
			}
			return nil, err
		}
	}

	// This represents the elapsed time between the proxy request being received until
	// we attempt to dial the remote host. This is intended to measure the latency
	// cost incurred by Smokescreen.
	sctx.cfg.MetricsClient.Timing("proxy_duration_ms", time.Since(sctx.start), 1)

	var conn net.Conn
	var err error

	start := time.Now()
	if sctx.cfg.ProxyDialTimeout == nil {
		conn, err = net.DialTimeout(network, d.ResolvedAddr.String(), sctx.cfg.ConnectTimeout)
	} else {
		conn, err = sctx.cfg.ProxyDialTimeout(ctx, network, d.ResolvedAddr.String(), sctx.cfg.ConnectTimeout)
	}
	connTime := time.Since(start)
	sctx.Logger = sctx.Logger.WithFields(dialContextLoggerFields(pctx, sctx, conn, connTime))

	if sctx.cfg.TimeConnect {
		sctx.cfg.MetricsClient.Timing("cn.atpt.connect.time", connTime, 1)
	}

	if err != nil {
		sctx.cfg.MetricsClient.IncrWithTags("cn.atpt.total", map[string]string{"success": "false"}, 1)
		sctx.cfg.ConnTracker.RecordAttempt(sctx.RequestedHost, false)
		metrics.ReportConnError(sctx.cfg.MetricsClient, err)
		return nil, err
	}
	sctx.cfg.MetricsClient.IncrWithTags("cn.atpt.total", map[string]string{"success": "true"}, 1)
	sctx.cfg.ConnTracker.RecordAttempt(sctx.RequestedHost, true)

	// Only wrap CONNECT conns with an InstrumentedConn. Connections used for traditional HTTP proxy
	// requests are pooled and reused by net.Transport.
	if sctx.ProxyType == connectProxy {
		ic := sctx.cfg.ConnTracker.NewInstrumentedConnWithTimeout(conn, sctx.cfg.IdleTimeout, sctx.Logger, d.Role, d.OutboundHost, sctx.ProxyType, d.Project)
		pctx.ConnErrorHandler = ic.Error
		conn = ic
	} else {
		conn = NewTimeoutConn(conn, sctx.cfg.IdleTimeout)
	}

	return conn, nil
}
func dialContextLoggerFields(pctx *goproxy.ProxyCtx, sctx *SmokescreenContext, conn net.Conn, connTime time.Duration) logrus.Fields {
	fields := logrus.Fields{
		LogFieldConnEstablishMS: connTime.Milliseconds(),
	}
	if conn != nil {
		if addr := conn.LocalAddr(); addr != nil {
			fields[LogFieldOutLocalAddr] = addr.String()
		}

		if addr := conn.RemoteAddr(); addr != nil {
			fields[LogFieldOutRemoteAddr] = addr.String()
		}
	}
	// If we have a MITM and option is enabled, we can add detailed Request log fields
	if pctx.ConnectAction == goproxy.ConnectMitm && sctx.Decision.MitmConfig != nil && sctx.Decision.MitmConfig.DetailedHttpLogs {
		fields[LogMitmReqUrl] = pctx.Req.URL.String()
		fields[LogMitmReqMethod] = pctx.Req.Method
		fields[LogMitmReqHeaders] = redactHeaders(pctx.Req.Header, sctx.Decision.MitmConfig.DetailedHttpLogsFullHeaders)
	}

	return fields
}

// HTTPErrorHandler allows returning a custom error response when smokescreen
// fails to connect to the proxy target.
func HTTPErrorHandler(w io.WriteCloser, pctx *goproxy.ProxyCtx, err error) {
	sctx := pctx.UserData.(*SmokescreenContext)
	resp := rejectResponse(pctx, err)

	if err := resp.Write(w); err != nil {
		sctx.Logger.Errorf("Failed to write HTTP error response: %s", err)
	}

	if err := w.Close(); err != nil {
		sctx.Logger.Errorf("Failed to close proxy client connection: %s", err)
	}
}

func rejectResponse(pctx *goproxy.ProxyCtx, err error) *http.Response {
	sctx := pctx.UserData.(*SmokescreenContext)

	var msg, status string
	var code int

	if e, ok := err.(net.Error); ok {
		// net.Dial timeout
		if e.Timeout() {
			status = "Gateway timeout"
			code = http.StatusGatewayTimeout
			msg = "Timed out connecting to remote host: " + e.Error()

		} else if e, ok := err.(*net.DNSError); ok {
			status = "Bad gateway"
			code = http.StatusBadGateway
			msg = "Failed to resolve remote hostname: " + e.Error()
		} else {
			status = "Bad gateway"
			code = http.StatusBadGateway
			msg = "Failed to connect to remote host: " + e.Error()
		}
	} else if e, ok := err.(denyError); ok {
		status = "Request rejected by proxy"
		code = http.StatusProxyAuthRequired
		msg = fmt.Sprintf(denyMsgTmpl, pctx.Req.Host, e.Error())
	} else {
		status = "Internal server error"
		code = http.StatusInternalServerError
		msg = "An unexpected error occurred: " + err.Error()
		sctx.Logger.WithField("error", err.Error()).Warn("rejectResponse called with unexpected error")
	}
	sctx.Logger = sctx.Logger.WithField("status_code", code)

	// Do not double log deny errors, they are logged in a previous call to logProxy.
	if _, ok := err.(denyError); !ok {
		sctx.Logger.Error(msg)
	}

	if sctx.cfg.AdditionalErrorMessageOnDeny != "" {
		msg = fmt.Sprintf("%s\n\n%s\n", msg, sctx.cfg.AdditionalErrorMessageOnDeny)
	}

	resp := goproxy.NewResponse(pctx.Req, goproxy.ContentTypeText, code, msg+"\n")
	resp.Status = status
	resp.ProtoMajor = pctx.Req.ProtoMajor
	resp.ProtoMinor = pctx.Req.ProtoMinor
	resp.Header.Set(errorHeader, msg)
	if sctx.cfg.RejectResponseHandler != nil {
		sctx.cfg.RejectResponseHandler(resp)
	}
	if sctx.cfg.RejectResponseHandlerWithCtx != nil {
		sctx.cfg.RejectResponseHandlerWithCtx(sctx, resp)
	}
	return resp
}

func configureTransport(tr *http.Transport, cfg *Config) {
	if cfg.TransportMaxIdleConns != 0 {
		tr.MaxIdleConns = cfg.TransportMaxIdleConns
	}

	if cfg.TransportMaxIdleConnsPerHost != 0 {
		tr.MaxIdleConnsPerHost = cfg.TransportMaxIdleConns
	}

	if cfg.IdleTimeout != 0 {
		tr.IdleConnTimeout = cfg.IdleTimeout
	}
}

func newContext(cfg *Config, proxyType string, req *http.Request) *SmokescreenContext {
	start := time.Now()

	fields := logrus.Fields{
		LogFieldID:            xid.New().String(),
		LogFieldInRemoteAddr:  req.RemoteAddr,
		LogFieldProxyType:     proxyType,
		LogFieldRequestedHost: req.Host,
		LogFieldStartTime:     start.UTC(),
		LogFieldTraceID:       req.Header.Get(traceHeader),
	}

	// Add TLS fields immediately if available
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		fields[LogFieldInRemoteX509CN] = req.TLS.PeerCertificates[0].Subject.CommonName
		var ouEntries = req.TLS.PeerCertificates[0].Subject.OrganizationalUnit
		if len(ouEntries) > 0 {
			fields[LogFieldInRemoteX509OU] = ouEntries[0]
		}
	}

	logger := cfg.Log.WithFields(fields)
	return &SmokescreenContext{
		cfg:           cfg,
		Logger:        logger,
		ProxyType:     proxyType,
		start:         start,
		RequestedHost: req.Host,
	}
}

func BuildProxy(config *Config) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer(
		goproxy.WithHttpProxyAddr(config.UpstreamHttpProxyAddr),
		goproxy.WithHttpsProxyAddr(config.UpstreamHttpsProxyAddr),
		goproxy.WithAddServerIpHeader(config.AddServerIpHeader),
	)
	proxy.Verbose = false

	// Add CRL verification to TLS config if CRL file is provided
	if config.TlsConfig != nil && config.CrlByAuthorityKeyId != nil {
		originalVerify := config.TlsConfig.VerifyPeerCertificate
		config.TlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			config.Log.WithFields(logrus.Fields{
				"rawCerts":       rawCerts,
				"verifiedChains": verifiedChains,
			}).Debug("VerifyPeerCertificate called")
			// First run the original verification if it exists
			if originalVerify != nil {
				if err := originalVerify(rawCerts, verifiedChains); err != nil {
					config.Log.WithFields(logrus.Fields{
						"error": err,
					}).Error("original verification failed")
					return err
				}
			}

			// Then check CRL for each certificate in the chain
			for _, chain := range verifiedChains {
				for _, cert := range chain {
					// Skip root CA as it's typically not in CRLs
					if cert.IsCA && bytes.Equal(cert.RawSubject, cert.RawIssuer) {
						config.Log.WithFields(logrus.Fields{
							"cert": cert.Subject.CommonName,
						}).Debug("skipping root CA")
						continue
					}

					// Get CRL for this certificate's issuer
					crl := config.CrlByAuthorityKeyId[string(cert.AuthorityKeyId)]
					if crl == nil {
						// No CRL for this issuer - could be a warning but let's allow for now
						config.Log.WithFields(logrus.Fields{
							"cert":           cert.Subject.CommonName,
							"authorityKeyId": hex.EncodeToString(cert.AuthorityKeyId),
						}).Warn("no CRL for certificate")
						continue
					}

					// Check if certificate is revoked
					for _, revoked := range crl.TBSCertList.RevokedCertificates {
						if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
							config.Log.WithFields(logrus.Fields{
								"cert":   cert.Subject.CommonName,
								"serial": cert.SerialNumber,
							}).Warn("certificate is revoked")
							return fmt.Errorf("certificate with serial number %v is revoked", cert.SerialNumber)
						}
						config.Log.WithFields(logrus.Fields{
							"cert":   cert.Subject.CommonName,
							"serial": cert.SerialNumber,
						}).Debug("certificate is not revoked")
					}
				}
			}
			return nil
		}
	}

	configureTransport(proxy.Tr, config)

	// dialContext will be invoked for both CONNECT and traditional proxy requests
	proxy.Tr.DialContext = dialContext

	// Use a custom goproxy.RoundTripperFunc to ensure that the correct context is attached to the request.
	// This is only used for non-CONNECT HTTP proxy requests. For connect requests, goproxy automatically
	// attaches goproxy.ProxyCtx prior to calling dialContext.
	rtFn := goproxy.RoundTripperFunc(func(req *http.Request, pctx *goproxy.ProxyCtx) (*http.Response, error) {
		ctx := context.WithValue(req.Context(), goproxy.ProxyContextKey, pctx)
		return proxy.Tr.RoundTrip(req.WithContext(ctx))
	})

	// Associate a timeout with the CONNECT proxy client connection
	if config.IdleTimeout != 0 {
		proxy.ConnectClientConnHandler = func(conn net.Conn) net.Conn {
			return NewTimeoutConn(conn, config.IdleTimeout)
		}
	}

	// Set upstream proxy hooks if configured
	if config.UpstreamProxyTLSConfigHandler != nil {
		proxy.UpstreamProxyTLSConfigHandler = config.UpstreamProxyTLSConfigHandler
	}
	if config.UpstreamProxyConnectReqHandler != nil {
		proxy.UpstreamProxyConnectReqHandler = config.UpstreamProxyConnectReqHandler
	}

	// Handle traditional HTTP proxy and MITM outgoing requests (smokescreen - remote )
	proxy.OnRequest().DoFunc(func(req *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Set this on every request as every request mints a new goproxy.ProxyCtx
		pctx.RoundTripper = rtFn

		// In the context of MITM request. Once the originating request (client - smokescreen) has been allowed
		// goproxy/https.go calls proxy.filterRequest on the outgoing request (smokescreen - remote host) which calls this function
		// in this case we ony want to configure the RoundTripper
		if pctx.ConnectAction == goproxy.ConnectMitm {
			return req, nil
		}

		// We are intentionally *not* setting pctx.HTTPErrorHandler because with traditional HTTP
		// proxy requests we are able to specify the request during the call to OnResponse().
		sctx := newContext(config, httpProxy, req)

		// Attach SmokescreenContext to goproxy.ProxyCtx
		pctx.UserData = sctx

		// Delete Smokescreen specific headers before goproxy forwards the request
		defer func() {
			req.Header.Del(roleHeader)
			req.Header.Del(traceHeader)
		}()

		sctx.Logger.WithField("url", req.RequestURI).Debug("received HTTP proxy request")
		// Build an address parsable by net.ResolveTCPAddr
		destination, err := hostport.NewWithScheme(req.Host, req.URL.Scheme, false)
		if err != nil {
			pctx.Error = denyError{err}
			return req, rejectResponse(pctx, pctx.Error)
		}

		sctx.Decision, sctx.lookupTime, pctx.Error = checkIfRequestShouldBeProxied(config, sctx, req, destination)
		setUpstreamProxyHeader(req, sctx.Decision.SelectedUpstreamProxy)

		// add context fields to all future log messages sent using this smokescreen context's Logger
		sctx.Logger = sctx.Logger.WithFields(extractContextLogFields(pctx, sctx))

		// Returning any kind of response in this handler is goproxy's way of short circuiting
		// the request. The original request will never be sent, and goproxy will invoke our
		// response filter attached via the OnResponse() handler.
		if pctx.Error != nil {
			return req, rejectResponse(pctx, pctx.Error)
		}
		if !sctx.Decision.allow {
			return req, rejectResponse(pctx, denyError{errors.New(sctx.Decision.Reason)})
		}

		// Call the custom request handler if it exists
		if config.PostDecisionRequestHandler != nil {
			err = config.PostDecisionRequestHandler(req)
			if err != nil {
				pctx.Error = denyError{err}
				return req, rejectResponse(pctx, pctx.Error)
			}
		}

		// Proceed with proxying the request
		return req, nil
	})

	// Handle CONNECT proxy to TLS & other TCP protocols destination
	proxy.OnRequest().HandleConnectFunc(func(_ string, pctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		pctx.UserData = newContext(config, connectProxy, pctx.Req)
		pctx.HTTPErrorHandler = HTTPErrorHandler

		// Defer logging the proxy event here because logProxy relies
		// on state set in handleConnect
		defer logProxy(pctx)
		defer pctx.Req.Header.Del(traceHeader)

		connectAction, destination, err := handleConnect(config, pctx)
		if err != nil {
			pctx.Resp = rejectResponse(pctx, err)
			return goproxy.RejectConnect, ""
		}
		return connectAction, destination
	})

	// Strangely, goproxy can invoke this same function twice for a single HTTP request.
	//
	// If a proxy request is rejected due to an ACL denial, the response passed to this
	// function was created by Smokescreen's call to rejectResponse() in the OnRequest()
	// handler. This only happens once. This is also the behavior for an allowed request
	// which is completed successfully.
	//
	// If a proxy request is allowed, but the RoundTripper returns an error fulfulling
	// the HTTP request, goproxy will invoke this OnResponse() filter twice. First this
	// function will be called with a nil response, and as a result this function will
	// return a response to send back to the proxy client using rejectResponse(). This
	// function will be called again with the previously returned response, which will
	// simply trigger the logHTTP function and return.
	proxy.OnResponse().DoFunc(func(resp *http.Response, pctx *goproxy.ProxyCtx) *http.Response {
		sctx := pctx.UserData.(*SmokescreenContext)

		if resp != nil && pctx.Error == nil && sctx.Decision.allow {
			if resp.Header.Get(errorHeader) != "" {
				resp.Header.Del(errorHeader)
			}
			if sctx.cfg.AcceptResponseHandler != nil {
				sctx.cfg.AcceptResponseHandler(sctx, resp)
			}
		}

		if resp == nil && pctx.Error != nil {
			return rejectResponse(pctx, pctx.Error)
		}

		// We don't want to log if the connection is a MITM as it will be done in HandleConnectFunc
		if pctx.ConnectAction != goproxy.ConnectMitm {
			// In case of an error, this function is called a second time to filter the
			// response we generate so this Logger will be called once.
			logProxy(pctx)
		}
		return resp
	})

	// This function will be called on the response to a successful https CONNECT request.
	// The goproxy OnResponse() function above is only called for non-https responses.
	if config.AcceptResponseHandler != nil {
		proxy.ConnectRespHandler = func(pctx *goproxy.ProxyCtx, resp *http.Response) error {

			sctx, ok := pctx.UserData.(*SmokescreenContext)
			if !ok {
				return fmt.Errorf("goproxy ProxyContext missing required UserData *SmokescreenContext")
			}
			return config.AcceptResponseHandler(sctx, resp)
		}
	}

	return proxy
}

func logProxy(pctx *goproxy.ProxyCtx) {
	sctx := pctx.UserData.(*SmokescreenContext)

	fields := logrus.Fields{}
	decision := sctx.Decision
	// If a lookup takes less than 1ms it will be rounded down to zero. This can separated from
	// actual failures where the default zero value will also have the error field set.
	fields[LogFieldDNSLookupTime] = sctx.lookupTime.Milliseconds()

	if pctx.Resp != nil {
		fields[LogFieldContentLength] = pctx.Resp.ContentLength
	}

	if sctx.Decision != nil {
		fields[LogFieldDecisionReason] = decision.Reason
		fields[LogFieldEnforceWouldDeny] = decision.enforceWouldDeny
		fields[LogFieldAllow] = decision.allow
	}

	err := pctx.Error
	if err != nil {
		fields[LogFieldError] = err.Error()
	}

	entry := sctx.Logger.WithFields(fields)
	var logMethod func(...interface{})
	if _, ok := err.(denyError); !ok && err != nil {
		logMethod = entry.Error
	} else if decision != nil && decision.allow {
		logMethod = entry.Info
	} else {
		logMethod = entry.Warn
	}
	logMethod(CanonicalProxyDecision)
}

func extractContextLogFields(pctx *goproxy.ProxyCtx, sctx *SmokescreenContext) logrus.Fields {
	fields := logrus.Fields{}

	// Retrieve information from the ACL decision
	decision := sctx.Decision
	if sctx.Decision != nil {
		fields[LogFieldRole] = decision.Role
		fields[LogFieldProject] = decision.Project
	}

	return fields
}

func handleConnect(config *Config, pctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string, error) {
	sctx := pctx.UserData.(*SmokescreenContext)

	// Check if requesting Role is allowed to talk to remote
	destination, err := hostport.New(pctx.Req.Host, false)
	if err != nil {
		pctx.Error = denyError{err}
		return nil, "", pctx.Error
	}

	// checkIfRequestShouldBeProxied can return an error if either the resolved address is disallowed,
	// or if there is a DNS resolution failure, or if the subsequent proxy host (specified by the
	// X-Https-Upstream-Proxy header in the CONNECT request to _this_ proxy) is disallowed.
	sctx.Decision, sctx.lookupTime, pctx.Error = checkIfRequestShouldBeProxied(config, sctx, pctx.Req, destination)
	setUpstreamProxyHeader(pctx.Req, sctx.Decision.SelectedUpstreamProxy)

	// add context fields to all future log messages sent using this smokescreen context's Logger
	sctx.Logger = sctx.Logger.WithFields(extractContextLogFields(pctx, sctx))
	if pctx.Error != nil {
		// DNS resolution failure
		return nil, "", pctx.Error
	}

	if !sctx.Decision.allow {
		return nil, "", denyError{errors.New(sctx.Decision.Reason)}
	}

	// Call the custom request handler if it exists
	if config.PostDecisionRequestHandler != nil {
		err = config.PostDecisionRequestHandler(pctx.Req)
		if err != nil {
			pctx.Error = denyError{err}
			return nil, "", pctx.Error
		}
	}

	connectAction := goproxy.OkConnect
	// If the ACLDecision matched a MITM rule
	if sctx.Decision.MitmConfig != nil {
		if config.MitmTLSConfig == nil {
			deny := denyError{errors.New("ACLDecision specified MITM but Smokescreen doesn't have MITM enabled")}
			sctx.Decision.allow = false
			sctx.Decision.MitmConfig = nil
			sctx.Decision.Reason = deny.Error()
			return nil, "", deny
		}
		mitm := sctx.Decision.MitmConfig

		var mitmMutateRequest func(req *http.Request, ctx *goproxy.ProxyCtx)

		if len(mitm.AddHeaders) > 0 {
			mitmMutateRequest = func(req *http.Request, ctx *goproxy.ProxyCtx) {
				for k, v := range mitm.AddHeaders {
					req.Header.Set(k, v)
				}
			}
		}

		connectAction = &goproxy.ConnectAction{
			Action:            goproxy.ConnectMitm,
			TLSConfig:         config.MitmTLSConfig,
			MitmMutateRequest: mitmMutateRequest,
		}
	}

	return connectAction, destination.String(), nil
}

func findListener(ip string, defaultPort uint16) (net.Listener, error) {
	if einhorn.IsWorker() {
		listener, err := einhorn.GetListener(0)
		if err != nil {
			return nil, err
		}

		return &einhornListener{Listener: listener}, err
	} else {
		return net.Listen("tcp", fmt.Sprintf("%s:%d", ip, defaultPort))
	}
}

func StartWithConfig(config *Config, quit <-chan interface{}) {
	config.Log.Println("starting")
	var err error

	if err = config.Validate(); err != nil {
		config.Log.Fatal("invalid config", err)
	}

	proxy := BuildProxy(config)
	listener := config.Listener

	if listener == nil {
		listener, err = findListener(config.Ip, config.Port)
		if err != nil {
			config.Log.Fatal("can't find listener", err)
		}
	}

	if config.SupportProxyProtocol {
		listener = &proxyproto.Listener{Listener: listener}
	}

	var handler http.Handler = proxy

	if config.Healthcheck != nil {
		handler = &HealthcheckMiddleware{
			Proxy:       handler,
			Healthcheck: config.Healthcheck,
		}
	}

	// TLS support
	if config.TlsConfig != nil {
		listener = tls.NewListener(listener, config.TlsConfig)
	}

	// Setup connection tracking if not already set in config
	if config.ConnTracker == nil {
		config.ConnTracker = conntrack.NewTracker(config.IdleTimeout, config.MetricsClient, config.Log, config.ShuttingDown, nil)
	}

	server := http.Server{
		Handler: handler,
	}

	// This sets an IdleTimeout on _all_ client connections. CONNECT requests
	// hijacked by goproxy inherit the deadline set here. The deadlines are
	// reset by the proxy.ConnectClientConnHandler, which wraps the hijacked
	// connection in a TimeoutConn which bumps the deadline for every read/write.
	if config.IdleTimeout != 0 {
		server.IdleTimeout = config.IdleTimeout
	}

	config.MetricsClient.SetStarted()
	config.ShuttingDown.Store(false)
	runServer(config, &server, listener, quit)
}

func runServer(config *Config, server *http.Server, listener net.Listener, quit <-chan interface{}) {
	// Runs the server and shuts it down when it receives a signal.
	//
	// Why aren't we using goji's graceful shutdown library? Great question!
	//
	// There are several things we might want to do when shutting down gracefully:
	// 1. close the listening socket (so that we don't accept *new* connections)
	// 2. close *existing* keepalive connections once they become idle
	//
	// goproxy hijacks the socket and interferes with goji's ability to do the
	// latter.  We instead pass InstrumentedConn objects, which wrap net.Conn,
	// into goproxy.  ConnTracker keeps a reference to these, which allows us to
	// know exactly how long to wait until the connection has become idle, and
	// then Close it.

	if len(config.StatsSocketDir) > 0 {
		config.StatsServer = StartStatsServer(config)
	}

	graceful := true
	kill := make(chan os.Signal, 1)
	signal.Notify(kill, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case <-kill:
			config.Log.Print("quitting gracefully")

		case <-quit:
			config.Log.Print("quitting now")
			graceful = false
		}
		config.ShuttingDown.Store(true)

		// Shutdown() will block until all connections are closed unless we
		// provide it with a cancellation context.
		timeout := config.ExitTimeout
		if !graceful {
			timeout = 10 * time.Second
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		err := server.Shutdown(ctx)
		if err != nil {
			config.Log.Errorf("error shutting down http server: %v", err)
		}
	}()

	if err := server.Serve(listener); err != http.ErrServerClosed {
		config.Log.Errorf("http serve error: %v", err)
	}

	if graceful {
		// Wait for all connections to close or become idle before
		// continuing in an attempt to shutdown gracefully.
		exit := make(chan ExitStatus, 1)

		// This subroutine blocks until all connections close.
		go func() {
			config.Log.Print("Waiting for all connections to close...")
			config.ConnTracker.Wg().Wait()
			config.Log.Print("All connections are closed. Continuing with shutdown...")
			exit <- Closed
		}()

		// Always wait for a maximum of config.ExitTimeout
		time.AfterFunc(config.ExitTimeout, func() {
			config.Log.Printf("ExitTimeout %v reached - timing out", config.ExitTimeout)
			exit <- Timeout
		})

		// Sometimes, connections don't close and remain in the idle state. This subroutine
		// waits until all open connections are idle before sending the exit signal.
		go func() {
			config.Log.Print("Waiting for all connections to become idle...")
			beginTs := time.Now()

			// If idleTimeout is set to 0, fall back to using the exit timeout to avoid
			// immediately closing active connections.
			idleTimeout := config.IdleTimeout
			if idleTimeout == 0 {
				idleTimeout = config.ExitTimeout
			}

			for {
				checkAgainIn := config.ConnTracker.MaybeIdleIn(idleTimeout)
				if checkAgainIn > 0 {
					if time.Since(beginTs) > config.ExitTimeout {
						config.Log.Print(fmt.Sprintf("Timed out at %v while waiting for all open connections to become idle.", config.ExitTimeout))
						exit <- Timeout
						break
					} else {
						config.Log.Print(fmt.Sprintf("There are still active connections. Waiting %v before checking again.", checkAgainIn))
						time.Sleep(checkAgainIn)
					}
				} else {
					config.Log.Print("All connections are idle. Continuing with shutdown...")
					exit <- Idle
					break
				}
			}
		}()

		// Wait for the exit signal.
		reason := <-exit
		config.Log.Print(fmt.Sprintf("%s: closing all remaining connections.", reason.String()))
	}

	// Close all open (and idle) connections to send their metrics to log.
	config.ConnTracker.Range(func(k, v interface{}) bool {
		k.(*conntrack.InstrumentedConn).Close()
		return true
	})

	if config.StatsServer != nil {
		config.StatsServer.Shutdown()
	}
}

// Extract the client's ACL Role from the HTTP request, using the configured
// RoleFromRequest function.  Returns the Role, or an error if the Role cannot
// be determined (including no RoleFromRequest configured), unless
// AllowMissingRole is configured, in which case an empty Role and no error is
// returned.
func getRole(config *Config, req *http.Request) (string, error) {
	var role string
	var err error

	if config.RoleFromRequest != nil {
		role, err = config.RoleFromRequest(req)
	} else {
		err = MissingRoleError("RoleFromRequest is not configured")
	}

	switch {
	case err == nil:
		return role, nil
	case IsMissingRoleError(err) && config.AllowMissingRole:
		return "", nil
	default:
		config.Log.WithFields(logrus.Fields{
			"error":              err,
			"is_missing_role":    IsMissingRoleError(err),
			"allow_missing_role": config.AllowMissingRole,
		}).Error("Unable to get role for request")
		return "", err
	}
}

// setUpstreamProxyHeader sets the X-Upstream-Https-Proxy header on the request if a proxy is configured.
func setUpstreamProxyHeader(req *http.Request, proxyURL string) {
	if proxyURL != "" {
		req.Header.Set("X-Upstream-Https-Proxy", proxyURL)
	}
}

func selectUpstreamProxy(config *Config, sctx *SmokescreenContext, decision *ACLDecision) {
	if config.UpstreamProxySelector != nil {
		proxyURL := config.UpstreamProxySelector(sctx, decision)
		if proxyURL != "" {
			decision.SelectedUpstreamProxy = proxyURL
			config.MetricsClient.Incr("upstream_proxy_selector.proxy_selected", 1)
			return
		}
	}
	decision.SelectedUpstreamProxy = decision.ClientRequestedProxy
}

func checkIfRequestShouldBeProxied(config *Config, sctx *SmokescreenContext, req *http.Request, destination hostport.HostPort) (*ACLDecision, time.Duration, error) {
	decision := checkACLsForRequest(config, req, destination)

	var lookupTime time.Duration
	if decision.allow {
		start := time.Now()
		hostPort := destination.String()
		resolved, reason, err := safeResolve(config, "tcp", hostPort)
		lookupTime = time.Since(start)
		if err != nil {
			if _, ok := err.(denyError); !ok {
				return decision, lookupTime, err
			}
			decision.Reason = fmt.Sprintf("%s. %s", err.Error(), reason)
			decision.allow = false
			decision.enforceWouldDeny = true
		} else {
			decision.ResolvedAddr = resolved
			selectUpstreamProxy(config, sctx, decision)
		}
	}

	return decision, lookupTime, nil
}

func checkACLsForRequest(config *Config, req *http.Request, destination hostport.HostPort) *ACLDecision {
	decision := &ACLDecision{
		OutboundHost: destination.String(),
	}

	// X-Upstream-Https-Proxy is a header that can be set by the client to specify
	// a _subsequent_ proxy to use for the CONNECT request. This is used to allow traffic
	// flow as in: client -(TLS)-> smokescreen -(TLS)-> external proxy -(TLS)-> destination.
	// Without this header, there's no way for the client to specify a subsequent proxy.
	// Also note - Get returns the first value for a given header, or the empty string,
	// which is the behavior we want here.
	clientProvidedProxy := req.Header.Get("X-Upstream-Https-Proxy")
	decision.ClientRequestedProxy = clientProvidedProxy

	if config.EgressACL == nil {
		decision.allow = true
		decision.Reason = "Egress ACL is not configured"
		return decision
	}

	role, roleErr := getRole(config, req)
	if roleErr != nil {
		config.MetricsClient.Incr("acl.role_not_determined", 1)
		decision.Reason = "Client role cannot be determined"
		return decision
	}

	decision.Role = role

	// This host validation prevents IPv6 addresses from being used as destinations.
	// Added for backwards compatibility.
	if strings.ContainsAny(destination.Host, ":") {
		decision.Reason = "Destination host cannot be determined"
		return decision
	}

	if clientProvidedProxy != "" {
		connectProxyUrl, err := url.Parse(clientProvidedProxy)
		if err == nil && connectProxyUrl.Hostname() == "" {
			err = errors.New("proxy header contains invalid URL. The correct format is https://[username:password@]my.proxy.srv:12345")
		}

		if err != nil {
			config.Log.WithFields(logrus.Fields{
				"error":               err,
				"role":                role,
				"upstream_proxy_name": req.Header.Get("X-Upstream-Https-Proxy"),
				"destination_host":    destination.Host,
				"kind":                "parse_failure",
			}).Error("Unable to parse X-Upstream-Https-Proxy header.")

			config.MetricsClient.Incr("acl.upstream_proxy_parse_error", 1)
			return decision
		}

		clientProvidedProxy = connectProxyUrl.Hostname()
	}

	ACLDecision, err := config.EgressACL.Decide(role, destination.Host, clientProvidedProxy)
	decision.Project = ACLDecision.Project
	decision.Reason = ACLDecision.Reason
	decision.MitmConfig = ACLDecision.MitmConfig
	if err != nil {
		config.Log.WithFields(logrus.Fields{
			"error": err,
			"role":  role,
		}).Warn("EgressAcl.Decide returned an error.")

		config.MetricsClient.Incr("acl.decide_error", 1)
		return decision
	}

	tags := map[string]string{
		"role":     metrics.SanitizeTagValue(decision.Role),
		"def_rule": fmt.Sprintf("%t", ACLDecision.Default),
		"project":  ACLDecision.Project,
	}

	switch ACLDecision.Result {
	case acl.Deny:
		decision.enforceWouldDeny = true
		config.MetricsClient.IncrWithTags("acl.deny", tags, 1)

	case acl.AllowAndReport:
		decision.enforceWouldDeny = true
		config.MetricsClient.IncrWithTags("acl.report", tags, 1)
		decision.allow = true

	case acl.Allow:
		// Well, everything is going as expected.
		decision.allow = true
		decision.enforceWouldDeny = false
		config.MetricsClient.IncrWithTags("acl.allow", tags, 1)
	default:
		config.Log.WithFields(logrus.Fields{
			"role":        role,
			"destination": destination.Host,
			"action":      ACLDecision.Result.String(),
		}).Warn("Unknown ACL action")
		decision.Reason = "Internal error"
		config.MetricsClient.IncrWithTags("acl.unknown_error", tags, 1)
	}

	return decision
}

func redactHeaders(originalHeaders http.Header, allowedHeaders []string) http.Header {
	// Create a new map to store the redacted headers
	redactedHeaders := make(http.Header)

	// Convert allowedHeaders to a map for faster lookup
	allowedHeadersMap := make(map[string]bool)
	for _, h := range allowedHeaders {
		allowedHeadersMap[strings.ToLower(h)] = true
	}

	// Iterate through the original headers
	for key, values := range originalHeaders {
		lowerKey := strings.ToLower(key)
		if allowedHeadersMap[lowerKey] {
			// If the header is in the allowed list, copy it as is
			redactedHeaders[key] = values
		} else {
			// If not, redact the values
			redactedValues := make([]string, len(values))
			for i := range values {
				redactedValues[i] = "[REDACTED]"
			}
			redactedHeaders[key] = redactedValues
		}
	}

	return redactedHeaders
}
