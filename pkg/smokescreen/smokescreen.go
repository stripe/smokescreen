package smokescreen

import (
	"crypto/tls"
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

type denyError struct {
	host   string
	reason string
}

func (d denyError) Error() string {
	return fmt.Sprintf(denyMsgTmpl, d.host, d.reason)
}

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

func safeResolve(config *Config, network, addr string) (string, error) {
	config.StatsdClient.Count("resolver.attempts_total", 1, []string{}, 0.3)
	resolved, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		config.StatsdClient.Count("resolver.errors_total", 1, []string{}, 0.3)
		return "", err
	}

	switch classifyIP(config, resolved.IP) {
	case IpOK:
		return resolved.String(), nil
	case IpOKBlacklistExempted:
		config.StatsdClient.Count("resolver.private_blacklist_exempted_total", 1, []string{}, 0.3)
		return resolved.String(), nil
	case IpDenyNotGlobalUnicast:
		config.StatsdClient.Count("resolver.illegal_total", 1, []string{}, 0.3)
		return "", denyError{addr, fmt.Sprintf("resolves to private address %s", resolved.IP)}
	case IpDenyBlacklist:
		config.StatsdClient.Count("resolver.illegal_total", 1, []string{}, 0.3)
		return "", denyError{addr, fmt.Sprintf("resolves to blacklisted address %s", resolved.IP)}
	default:
		panic("unknown IP type")
	}
}

func dial(config *Config, network, addr string) (net.Conn, error) {
	resolved, err := safeResolve(config, network, addr)
	if err != nil {
		return nil, err
	}

	return net.DialTimeout(network, resolved, config.ConnectTimeout)
}

func connectErrorResult(config *Config, ctx *goproxy.ProxyCtx, err error) (*goproxy.ConnectAction, string) {
	config.Log.Warn(err)
	ctx.Resp = errorResponse(ctx.Req, config, err)
	return goproxy.RejectConnect, ""
}

func errorResponse(req *http.Request, config *Config, err error) *http.Response {
	var msg string
	if _, ok := err.(denyError); ok {
		msg = err.Error()
	} else {
		msg = "unexpected error occurred"
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

func buildProxy(config *Config) *goproxy.ProxyHttpServer {
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
			}).Info("received HTTP proxy request")

		ctx.UserData = time.Now().Unix()

		err := checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
		req.Header.Del(roleHeader)
		if err != nil {
			return req, errorResponse(req, config, err)
		}

		return req, nil
	})

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		config.Log.WithFields(
			logrus.Fields{
				"remote": ctx.Req.RemoteAddr,
				"host":   host,
			}).Info("received CONNECT proxy request")

		// Check if requesting role is allowed to talk to remote
		var resolved string
		err := checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
		if err != nil {
			return connectErrorResult(config, ctx, err)
		}

		resolved, err = safeResolve(config, "tcp", host)
		if err != nil {
			return connectErrorResult(config, ctx, err)
		}

		ctx.UserData = time.Now().Unix()
		logHttpsRequest(config, ctx, resolved)
		return goproxy.OkConnect, resolved
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if ctx.RoundTrip != nil {
			logResponse(config, ctx)
		}
		if resp != nil {
			resp.Header.Del(errorHeader)
		}
		if resp == nil && ctx.Error != nil {
			resp = errorResponse(ctx.Req, config, ctx.Error)
		}
		return resp
	})
	return proxy
}

func extractHostname(ctx *goproxy.ProxyCtx) string {
	return ctx.Req.Host
}

func logHttpsRequest(config *Config, ctx *goproxy.ProxyCtx, resolved string) {
	var contentLength int64
	if ctx.Resp != nil {
		contentLength = ctx.Resp.ContentLength
	}
	hostname := extractHostname(ctx)
	from_host, from_port, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
	to_host, to_port, _ := net.SplitHostPort(resolved)

	serviceName, serviceNameErr := config.RoleFromRequest(ctx.Req)
	if serviceNameErr != nil {
		serviceName = ""
	}

	config.Log.WithFields(
		logrus.Fields{
			"proxy_type":     "connect",
			"known_role":     serviceNameErr == nil || serviceName != "",
			"role":           serviceName,
			"src_host":       from_host,
			"src_port":       from_port,
			"host":           hostname,
			"dest_ip":        to_host,
			"dest_port":      to_port,
			"start_time":     ctx.UserData,
			"end_time":       time.Now().Unix(),
			"content_length": contentLength,
		}).Info("completed response")
}

func logResponse(config *Config, ctx *goproxy.ProxyCtx) {
	var contentLength int64
	if ctx.RoundTrip == nil || ctx.RoundTrip.TCPAddr == nil {
		// Reasons this might happen:
		// 1) IpTypePrivate ip destination (eg. 192.168.0.0/16, 10.0.0.0/8, etc)
		// 2) Destination that doesn't respond (eg. i/o timeout)
		// 3) destination domain that doesn't resolve
		// 4) bogus IP address (eg. 1154.218.100.183)
		config.Log.Println("Could not log response: missing IP address")
		return
	}
	if ctx.Resp != nil {
		contentLength = ctx.Resp.ContentLength
	}
	from_host, from_port, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
	hostname := extractHostname(ctx)

	serviceName, serviceNameErr := config.RoleFromRequest(ctx.Req)
	if serviceNameErr != nil {
		serviceName = ""
	}

	config.Log.WithFields(
		logrus.Fields{
			"proxy_type":     "http",
			"known_role":     serviceNameErr == nil || serviceName != "",
			"role":           serviceName,
			"src_host":       from_host,
			"src_port":       from_port,
			"host":           hostname,
			"dest_ip":        ctx.RoundTrip.TCPAddr.IP.String(),
			"dest_port":      ctx.RoundTrip.TCPAddr.Port,
			"start_time":     ctx.UserData,
			"end_time":       time.Now().Unix(),
			"content_length": contentLength,
		}).Info("completed response")
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
	proxy := buildProxy(config)

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

func checkIfRequestShouldBeProxied(config *Config, req *http.Request, outboundHost string) error {
	if config.EgressAcl != nil {
		role, roleErr := config.RoleFromRequest(req)
		if roleErr != nil {
			// A missing role is OK at this point since we may have a default
			if _, ok := roleErr.(MissingRoleError); !ok {
				return roleErr
			}
		}

		project := ""
		project, projectErr := config.EgressAcl.Project(role)

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
				return denyError{outboundHost, msg}
			}
			return err
		}

		switch result {
		case EgressAclDecisionDeny:
			config.Log.WithFields(
				logrus.Fields{
					"proxied":       false,
					"known_project": projectErr == nil,
					"project":       project,
					"known_role":    role != "",
					"client_role":   role,
					"outbound_host": outboundHost,
				}).Warn("request denied by acl")
			return denyError{
				outboundHost,
				fmt.Sprintf("your role '%s' is not allowed to access this host", role),
			}

		case EgressAclDecisionAllowAndReport:

			config.Log.WithFields(
				logrus.Fields{
					"proxied":       true,
					"known_project": projectErr == nil,
					"project":       project,
					"known_role":    role != "",
					"client_role":   role,
					"outbound_host": outboundHost,
				}).Info("unknown egress reported")

		case EgressAclDecisionAllow:
			// Well, everything is going as expected.
		}
	}
	return nil
}
