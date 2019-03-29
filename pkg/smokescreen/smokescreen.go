package smokescreen

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/armon/go-proxyproto"
	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"github.com/stripe/go-einhorn/einhorn"
)

const (
	ipAllowDefault ipType = iota
	ipAllowUserConfigured
	ipDenyNotGlobalUnicast
	ipDenyPrivateRange
	ipDenyUserConfigured

	denyMsgTmpl = "Egress proxying is denied to host '%s': %s."
)

var LOGLINE_CANONICAL_PROXY_DECISION = "CANONICAL-PROXY-DECISION"

type ipType int

type aclDecision struct {
	reason, role, project, outboundHost string
	allow                               bool
	enforceWouldDeny                    bool
}

type ctxUserData struct {
	start    time.Time
	decision *aclDecision
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
	default:
		panic(fmt.Errorf("unknown ip type %d", t))
	}
}

const errorHeader = "X-Smokescreen-Error"
const roleHeader = "X-Smokescreen-Role"

func ipIsInSetOfNetworks(nets []net.IPNet, ip net.IP) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func classifyIP(config *Config, ip net.IP) ipType {
	if !ip.IsGlobalUnicast() || ip.IsLoopback() {
		if ipIsInSetOfNetworks(config.AllowRanges, ip) {
			return ipAllowUserConfigured
		} else {
			return ipDenyNotGlobalUnicast
		}
	}

	if ipIsInSetOfNetworks(config.AllowRanges, ip) {
		return ipAllowUserConfigured
	} else if ipIsInSetOfNetworks(config.DenyRanges, ip) {
		return ipDenyUserConfigured
	} else if ipIsInSetOfNetworks(PrivateNetworkRanges, ip) {
		return ipDenyPrivateRange
	} else {
		return ipAllowDefault
	}
}

func safeResolve(config *Config, network, addr string) (*net.TCPAddr, error) {
	config.StatsdClient.Incr("resolver.attempts_total", []string{}, 1)
	resolved, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		config.StatsdClient.Incr("resolver.errors_total", []string{}, 1)
		return nil, err
	}

	classification := classifyIP(config, resolved.IP)
	config.StatsdClient.Incr(classification.statsdString(), []string{}, 1)

	if classification.IsAllowed() {
		return resolved, nil
	}
	return nil, denyError{fmt.Errorf("The destination address (%s) was denied by rule '%s'", resolved.IP, classification)}
}

func dial(config *Config, network, addr string, userdata interface{}) (net.Conn, error) {
	var role, outboundHost string

	if v, ok := userdata.(*ctxUserData); ok {
		role = v.decision.role
		outboundHost = v.decision.outboundHost
	}

	resolved, err := safeResolve(config, network, addr)
	if err != nil {
		return nil, err
	}

	config.StatsdClient.Incr("cn.atpt.total", []string{}, 1)
	conn, err := net.DialTimeout(network, resolved.String(), config.ConnectTimeout)

	if err != nil {
		config.StatsdClient.Incr("cn.atpt.fail.total", []string{}, 1)
		return nil, err
	} else {
		config.StatsdClient.Incr("cn.atpt.success.total", []string{}, 1)
		return NewConnExt(conn, config, role, outboundHost, time.Now()), nil
	}
}

func rejectResponse(req *http.Request, config *Config, err error) *http.Response {
	var msg string
	switch err.(type) {
	case denyError:
		msg = fmt.Sprintf(denyMsgTmpl, req.Host, err.Error())
	default:
		config.Log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("rejectResponse called with unexpected error")
		msg = "An unexpected error occurred."
	}

	if config.AdditionalErrorMessageOnDeny != "" {
		msg = fmt.Sprintf("%s\n\n%s\n", msg, config.AdditionalErrorMessageOnDeny)
	}

	resp := goproxy.NewResponse(req,
		goproxy.ContentTypeText,
		http.StatusServiceUnavailable,
		msg+"\n")
	resp.ProtoMajor = req.ProtoMajor
	resp.ProtoMinor = req.ProtoMinor
	resp.Header.Set(errorHeader, msg)
	return resp
}

func BuildProxy(config *Config) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Tr.Dial = func(network, addr string, userdata interface{}) (net.Conn, error) {
		return dial(config, network, addr, userdata)
	}

	// Ensure that we don't keep old connections alive to avoid TLS errors
	// when attempting to re-use an idle connection.
	proxy.Tr.DisableKeepAlives = true

	// Handle traditional HTTP proxy
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		userData := ctxUserData{time.Now(), nil}
		ctx.UserData = &userData

		config.Log.WithFields(
			logrus.Fields{
				"source_ip":      ctx.Req.RemoteAddr,
				"requested_host": ctx.Req.Host,
				"url":            ctx.Req.RequestURI,
			}).Debug("received HTTP proxy request")

		userData.decision = checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
		req.Header.Del(roleHeader)
		if !userData.decision.allow {
			return req, rejectResponse(req, config, denyError{errors.New(userData.decision.reason)})
		}

		// Proceed with proxying the request
		return req, nil
	})

	// Handle CONNECT proxy to TLS & other TCP protocols destination
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		ctx.UserData = &ctxUserData{time.Now(), nil}
		resolved, err := handleConnect(config, ctx)
		if err != nil {
			ctx.Resp = rejectResponse(ctx.Req, config, err)
			return goproxy.RejectConnect, ""
		}
		return goproxy.OkConnect, resolved.String()
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil {
			resp.Header.Del(errorHeader)
		}

		if resp == nil && ctx.Error != nil {
			return rejectResponse(ctx.Req, config, ctx.Error)
		}

		// In case of an error, this function is called a second time to filter the
		// response we generate so this logger will be called once.
		logHTTP(config, ctx)
		return resp
	})
	return proxy
}

func logProxy(
	config *Config,
	ctx *goproxy.ProxyCtx,
	proxyType string,
	toAddress *net.TCPAddr,
	decision *aclDecision,
	start time.Time,
	err error,
) {
	var contentLength int64
	if ctx.Resp != nil {
		contentLength = ctx.Resp.ContentLength
	}

	fromHost, fromPort, _ := net.SplitHostPort(ctx.Req.RemoteAddr)

	allow := err == nil

	fields := logrus.Fields{
		"proxy_type":     proxyType,
		"src_host":       fromHost,
		"src_port":       fromPort,
		"requested_host": ctx.Req.Host,
		"start_time":     start.Unix(),
		"content_length": contentLength,
	}

	if _, ok := err.(denyError); !ok && err != nil {
		fields["error"] = err
	}

	if toAddress != nil {
		fields["dest_ip"] = toAddress.IP.String()
		fields["dest_port"] = toAddress.Port
	}

	if decision != nil {
		fields["role"] = decision.role
		fields["project"] = decision.project
		fields["decision_reason"] = decision.reason
		fields["enforce_would_deny"] = decision.enforceWouldDeny

		if !decision.allow {
			allow = false
		}
	}
	fields["allow"] = allow

	entry := config.Log.WithFields(fields)
	var logMethod func(...interface{})
	if _, ok := fields["error"]; ok {
		logMethod = entry.Error
	} else if allow {
		logMethod = entry.Info
	} else {
		logMethod = entry.Warn
	}
	logMethod(LOGLINE_CANONICAL_PROXY_DECISION)
}

func logHTTP(config *Config, ctx *goproxy.ProxyCtx) {
	var toAddr *net.TCPAddr
	if ctx.RoundTrip != nil {
		toAddr = ctx.RoundTrip.TCPAddr
	}

	userData := ctx.UserData.(*ctxUserData)

	logProxy(config, ctx, "http", toAddr, userData.decision, userData.start, ctx.Error)
}

func handleConnect(config *Config, ctx *goproxy.ProxyCtx) (*net.TCPAddr, error) {
	config.Log.WithFields(
		logrus.Fields{
			"remote":         ctx.Req.RemoteAddr,
			"requested_host": ctx.Req.Host,
		}).Debug("received CONNECT proxy request")
	start := time.Now()

	// Check if requesting role is allowed to talk to remote
	var resolved *net.TCPAddr
	var err error
	var decision *aclDecision
	defer func() {
		logProxy(config, ctx, "connect", resolved, decision, start, err)
	}()

	decision = checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
	ctx.UserData.(*ctxUserData).decision = decision
	if !decision.allow {
		return nil, denyError{errors.New(decision.reason)}
	}

	resolved, err = safeResolve(config, "tcp", ctx.Req.Host)
	if err != nil {
		return nil, err
	}

	return resolved, nil
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
	proxy := BuildProxy(config)

	listener, err := findListener(config.Ip, config.Port)
	if err != nil {
		config.Log.Fatal("can't find listener", err)
	}

	if config.SupportProxyProtocol {
		listener = &proxyproto.Listener{Listener: listener}
	}

	var handler http.Handler = proxy
	if config.MaintenanceFile != "" {
		handler = &HealthcheckMiddleware{
			App:             handler,
			MaintenanceFile: config.MaintenanceFile,
			StatsdClient:    config.StatsdClient,
		}
	}

	// TLS support

	if config.TlsConfig != nil {
		listener = tls.NewListener(listener, config.TlsConfig)
	}

	server := http.Server{
		Handler: handler,
	}

	runServer(config, &server, listener, quit)
	return
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
	// It is impossible to close existing keepalive connections, because goproxy
	// hijacks the socket and doesn't tell us when they become idle. So all we
	// can do is close the listening socket when we receive a signal, not accept
	// new connections, and then exit the program after a timeout.

	if len(config.StatsSocketDir) > 0 {
		config.StatsServer = StartStatsServer(config)
	}

	semiGraceful := true
	kill := make(chan os.Signal, 1)
	signal.Notify(kill, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case <-kill:
			config.Log.Print("quitting semi-gracefully")

		case <-quit:
			config.Log.Print("quitting now")
			semiGraceful = false
		}
		listener.Close()
	}()
	err := server.Serve(listener)
	if !strings.HasSuffix(err.Error(), "use of closed network connection") {
		config.Log.Fatal(err)
	}

	if semiGraceful {
		// the program has exited normally, wait 60s in an attempt to shutdown
		// semi-gracefully
		config.Log.WithField("delay", config.ExitTimeout).Info("Waiting before shutting down")
		time.Sleep(config.ExitTimeout)
	}

	if config.StatsServer != nil {
		config.StatsServer.(*StatsServer).Shutdown()
	}
}

// Extract the client's ACL role from the HTTP request, using the configured
// RoleFromRequest function.  Returns the role, or an error if the role cannot
// be determined (including no RoleFromRequest configured), unless
// AllowMissingRole is configured, in which case an empty role and no error is
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

func checkIfRequestShouldBeProxied(config *Config, req *http.Request, outboundHost string) *aclDecision {
	decision := &aclDecision{
		outboundHost: outboundHost,
	}

	if config.EgressAcl == nil {
		decision.allow = true
		decision.reason = "Egress ACL is not configured"
		return decision
	}

	role, roleErr := getRole(config, req)
	if roleErr != nil {
		config.StatsdClient.Incr("acl.role_not_determined", []string{}, 1)
		decision.reason = "Client role cannot be determined"
		return decision
	}

	decision.role = role
	decision.project, _ = config.EgressAcl.Project(role)

	submatch := hostExtractRE.FindStringSubmatch(outboundHost)
	destination := submatch[1]

	action, defaultRuleUsed, err := config.EgressAcl.Decide(role, destination)
	if err != nil {
		config.Log.WithFields(logrus.Fields{
			"error": err,
			"role":  role,
		}).Warn("EgressAcl.Decide returned an error.")

		config.StatsdClient.Incr("acl.decide_error", []string{}, 1)
		decision.reason = "acl.decide error"
		return decision
	}

	tags := []string{
		fmt.Sprintf("role:%s", decision.role),
		fmt.Sprintf("def_rule:%t", defaultRuleUsed),
	}

	switch action {
	case EgressAclDecisionDeny:
		decision.reason = "Role is not allowed to access this host"
		decision.enforceWouldDeny = true
		config.StatsdClient.Incr("acl.deny", tags, 1)

	case EgressAclDecisionAllowAndReport:
		decision.reason = "Role is not allowed to access this host but report_only is true"
		decision.enforceWouldDeny = true
		config.StatsdClient.Incr("acl.report", tags, 1)
		decision.allow = true

	case EgressAclDecisionAllow:
		// Well, everything is going as expected.
		decision.allow = true
		decision.reason = "Role is allowed to access this host"
		decision.enforceWouldDeny = false
		config.StatsdClient.Incr("acl.allow", tags, 1)
	default:
		config.Log.WithFields(logrus.Fields{
			"role":        role,
			"destination": destination,
			"action":      action,
		}).Warn("Unknown ACL action")
		decision.reason = "Internal error"
		config.StatsdClient.Incr("acl.unknown_error", tags, 1)
	}
	return decision
}
