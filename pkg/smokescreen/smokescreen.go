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
	IpOK IpType = iota
	IpOKBlacklistExempted
	IpDenyNotGlobalUnicast
	IpDenyBlacklist

	denyMsgTmpl = "egress proxying denied to host '%s' because %s. " +
		"If you didn't intend for your request to be proxied, you may want a 'no_proxy' environment variable."
)

type IpType int

type aclDecision struct {
	reason, role, project string
	allow                 bool
}

type ctxUserData struct {
	start    time.Time
	decision *aclDecision
}

type denyError error

func (t IpType) String() string {
	switch t {
	case IpOK:
		return "IpOK"
	case IpOKBlacklistExempted:
		return "IpOKBlacklistExempted"
	case IpDenyNotGlobalUnicast:
		return "IpDenyNotGlobalUnicast"
	case IpDenyBlacklist:
		return "IpDenyBlacklist"
	default:
		panic(fmt.Sprintf("unknown ip type %d", t))
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

func classifyIP(config *Config, ip net.IP) IpType {
	if !(ip.IsGlobalUnicast() || (config.AllowProxyToLoopback && ip.IsLoopback())) {
		return IpDenyNotGlobalUnicast
	}

	blacklisted := ipIsInSetOfNetworks(config.CidrBlacklist, ip)
	whitelisted := ipIsInSetOfNetworks(config.CidrBlacklistExemptions, ip)

	if !blacklisted {
		return IpOK
	} else if whitelisted {
		return IpOKBlacklistExempted
	}

	return IpDenyBlacklist
}

func safeResolve(config *Config, network, addr string) (*net.TCPAddr, error) {
	config.StatsdClient.Count("resolver.attempts_total", 1, []string{}, 0.3)
	resolved, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		config.StatsdClient.Count("resolver.errors_total", 1, []string{}, 0.3)
		return nil, err
	}

	classification := classifyIP(config, resolved.IP)
	switch classification {
	case IpOK:
		return resolved, nil
	case IpOKBlacklistExempted:
		config.StatsdClient.Count("resolver.private_blacklist_exempted_total", 1, []string{}, 0.3)
		return resolved, nil
	case IpDenyNotGlobalUnicast:
		config.StatsdClient.Count("resolver.illegal_total", 1, []string{}, 0.3)
		return nil, denyError(fmt.Errorf("resolves to private address %s", resolved.IP))
	case IpDenyBlacklist:
		config.StatsdClient.Count("resolver.illegal_total", 1, []string{}, 0.3)
		return nil, denyError(fmt.Errorf("resolves to blacklisted address %s", resolved.IP))
	default:
		return nil, fmt.Errorf("unknown IP type %v", classification)
	}
}

func dial(config *Config, network, addr string) (net.Conn, error) {
	resolved, err := safeResolve(config, network, addr)
	if err != nil {
		return nil, err
	}

	return net.DialTimeout(network, resolved.String(), config.ConnectTimeout)
}

func rejectResponse(req *http.Request, config *Config, err error) *http.Response {
	var msg string
	switch err.(type) {
	case denyError:
		msg = fmt.Sprintf(denyMsgTmpl, req.Host, err.Error())
	default:
		msg = "an unexpected error occurred."
	}

	if config.AdditionalErrorMessageOnDeny != "" {
		msg += " "
		msg += config.AdditionalErrorMessageOnDeny
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
	proxy.Tr.Dial = func(network, addr string) (net.Conn, error) {
		return dial(config, network, addr)
	}

	// Handle traditional HTTP proxy
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		config.Log.WithFields(
			logrus.Fields{
				"remote": ctx.Req.RemoteAddr,
				"host":   ctx.Req.Host,
				"url":    ctx.Req.RequestURI,
			}).Debug("received HTTP proxy request")
		userData := ctxUserData{time.Now(), nil}
		ctx.UserData = &userData

		var err error
		userData.decision, err = checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
		req.Header.Del(roleHeader)
		if err != nil {
			return req, rejectResponse(req, config, err)
		}
		if !userData.decision.allow {
			return req, rejectResponse(req, config, denyError(errors.New(userData.decision.reason)))
		}

		return req, nil
	})

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
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

	hostname := ctx.Req.Host
	fromHost, fromPort, _ := net.SplitHostPort(ctx.Req.RemoteAddr)

	allow := err == nil

	fields := logrus.Fields{
		"proxy_type":     proxyType,
		"src_host":       fromHost,
		"src_port":       fromPort,
		"host":           hostname,
		"start_time":     start.Unix(),
		"end_time":       time.Now().Unix(),
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
	logMethod("proxy_response")
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
			"remote": ctx.Req.RemoteAddr,
			"host":   ctx.Req.Host,
		}).Debug("received CONNECT proxy request")
	start := time.Now()

	// Check if requesting role is allowed to talk to remote
	var resolved *net.TCPAddr
	var err error
	var decision *aclDecision
	defer func() {
		logProxy(config, ctx, "connect", resolved, decision, start, err)
	}()

	decision, err = checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
	if err != nil {
		return nil, err
	}
	if !decision.allow {
		return nil, denyError(errors.New(decision.reason))
	}

	resolved, err = safeResolve(config, "tcp", ctx.Req.Host)
	if err != nil {
		return nil, err
	}

	return resolved, nil
}

func findListener(ip string, defaultPort int) (net.Listener, error) {
	if einhorn.IsWorker() {
		listener, err := einhorn.GetListener(0)
		if err != nil {
			return nil, err
		}

		err = einhorn.Ack()

		return listener, err
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
}

func checkIfRequestShouldBeProxied(config *Config, req *http.Request, outboundHost string) (*aclDecision, error) {
	decision := &aclDecision{}

	if config.EgressAcl == nil {
		decision.allow = true
		decision.reason = "no egress ACL configured"
		return decision, nil
	}

	role, roleErr := config.RoleFromRequest(req)
	if roleErr != nil {
		// A missing role is OK at this point since we may have a default
		if _, ok := roleErr.(MissingRoleError); !ok {
			return nil, roleErr
		}
	}
	decision.role = role

	decision.project, _ = config.EgressAcl.Project(role)

	submatch := config.hostExtractExpr.FindStringSubmatch(outboundHost)

	result, err := config.EgressAcl.Decide(role, submatch[1])
	if err != nil {
		if rerr, ok := err.(UnknownRoleError); ok {
			var msg string
			if roleErr != nil {
				msg = fmt.Sprintf("unable to extract a role from your request and no default is provided (%s)", err.Error())
			} else {
				msg = fmt.Sprintf("you passed an unknown role '%s'", rerr.Role)
			}
			decision.reason = msg
			return decision, nil
		}
		return nil, err
	}

	switch result {
	case EgressAclDecisionDeny:
		decision.reason = "role is not allowed to access this host"
		return decision, nil

	case EgressAclDecisionAllowAndReport:
		decision.reason = "role is not allowed to access this host but report_only is true"
		decision.allow = true
		return decision, nil

	case EgressAclDecisionAllow:
		// Well, everything is going as expected.
		decision.allow = true
		decision.reason = "your role is allowed to access this host"
		return decision, nil
	default:
		return nil, fmt.Errorf("unknown acl decision %v", result)
	}
}
