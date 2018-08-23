package smoker

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
	log "github.com/sirupsen/logrus"
	"github.com/stripe/go-einhorn/einhorn"
)

type IpType int

const (
	IpTypePublic IpType = iota
	IpTypePrivate
	IpTypeBlacklistExempted
)

func (t IpType) String() string {
	switch t {
	case IpTypePublic:
		return "IpTypePublic"
	case IpTypePrivate:
		return "IpTypePrivate"
	case IpTypeBlacklistExempted:
		return "IpTypeBlacklistExempted"
	default:
		panic(fmt.Sprintf("unknown ip type %d", t))
	}
}

const errorHeader = "X-Smokescreen-Error"
const roleHeader = "X-Smokescreen-Role"

func isPrivateNetwork(nets []net.IPNet, ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return true
	}
	return ipIsInSetOfNetworks(nets, ip)
}

func isWhitelistNetwork(nets []net.IPNet, ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	return ipIsInSetOfNetworks(nets, ip)
}

func ipIsInSetOfNetworks(nets []net.IPNet, ip net.IP) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func classifyIP(config *Config, ip net.IP) IpType {
	if isPrivateNetwork(config.CidrBlacklist, ip) {
		if isWhitelistNetwork(config.CidrBlacklistExemptions, ip) {
			return IpTypeBlacklistExempted
		} else {
			return IpTypePrivate
		}
	} else {
		return IpTypePublic
	}
}

func safeResolve(config *Config, network, addr string) (string, error) {
	config.StatsdClient.Count("resolver.attempts_total", 1, []string{}, 0.3)
	resolved, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		config.StatsdClient.Count("resolver.errors_total", 1, []string{}, 0.3)
		return "", err
	}

	if config.AllowPrivateRange {
		return resolved.String(), nil
	}

	switch classifyIP(config, resolved.IP) {
	case IpTypePublic:
		return resolved.String(), nil
	case IpTypeBlacklistExempted:
		config.StatsdClient.Count("resolver.private_blacklist_exempted_total", 1, []string{}, 0.3)
		return resolved.String(), nil
	default:
		config.StatsdClient.Count("resolver.illegal_total", 1, []string{}, 0.3)
		return "", fmt.Errorf("host %s resolves to illegal IP %s",
			addr, resolved.IP)
	}
}

func dial(config *Config, network, addr string) (net.Conn, error) {
	resolved, err := safeResolve(config, network, addr)
	if err != nil {
		return nil, err
	}

	return net.DialTimeout(network, resolved, config.ConnectTimeout)
}

func errorResponse(req *http.Request, err error) *http.Response {
	resp := goproxy.NewResponse(req,
		goproxy.ContentTypeText,
		http.StatusServiceUnavailable,
		err.Error()+"\n")
	resp.ProtoMajor = req.ProtoMajor
	resp.ProtoMinor = req.ProtoMinor
	resp.Header.Set(errorHeader, err.Error())
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
		ctx.Logf("Received HTTP proxy request: "+
			"remote=%#v host=%#v url=%#v",
			ctx.Req.RemoteAddr,
			ctx.Req.Host,
			ctx.Req.RequestURI)
		ctx.UserData = time.Now().Unix()

		shouldProxy := checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
		req.Header.Del(roleHeader)
		if shouldProxy {
			return req, nil
		} else {
			return req, errorResponse(req, fmt.Errorf(config.ErrorMessageOnDeny))
		}
	})

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {

		ctx.Logf("Received CONNECT proxy request: "+
			"remote=%#v host=%#v",
			ctx.Req.RemoteAddr,
			host)

		// Check if requesting role is allowed to talk to remote
		shouldProxy := checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
		if shouldProxy {
			resolved, err := safeResolve(config, "tcp", host)
			if err != nil {
				fmt.Printf("Err %#v", err)
				ctx.Resp = errorResponse(ctx.Req, err)
				return goproxy.RejectConnect, ""
			}
			ctx.UserData = time.Now().Unix()
			logHttpsRequest(ctx, resolved)
			return goproxy.OkConnect, resolved
		} else {
			return goproxy.RejectConnect, ""
		}
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if ctx.RoundTrip != nil {
			logResponse(config, ctx)
		}
		if resp != nil {
			resp.Header.Del(errorHeader)
		}
		if resp == nil && ctx.Error != nil {
			resp = errorResponse(ctx.Req, ctx.Error)
		}
		return resp
	})
	return proxy
}

func extractHostname(ctx *goproxy.ProxyCtx) string {
	return ctx.Req.Host
}

func logHttpsRequest(ctx *goproxy.ProxyCtx, resolved string) {
	var contentLength int64
	if ctx.Resp != nil {
		contentLength = ctx.Resp.ContentLength
	}
	hostname := extractHostname(ctx)
	from_host, from_port, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
	to_host, to_port, _ := net.SplitHostPort(resolved)
	log.Printf("Received CONNECT request: "+
		"proxy_type=connect src_host=%#v src_port=%s host=%#v dest_ip=%#v dest_port=%s start_time=%#v end_time=%d content_length=%#v\n",
		from_host,
		from_port,
		hostname,
		to_host,
		to_port,
		ctx.UserData,
		time.Now().Unix(),
		// The content length is often -1 because of HTTP chunked encoding. this is normal.
		contentLength,
	)
}

func logResponse(conf *Config, ctx *goproxy.ProxyCtx) {
	var contentLength int64
	if ctx.RoundTrip == nil || ctx.RoundTrip.TCPAddr == nil {
		// Reasons this might happen:
		// 1) IpTypePrivate ip destination (eg. 192.168.0.0/16, 10.0.0.0/8, etc)
		// 2) Destination that doesn't respond (eg. i/o timeout)
		// 3) destination domain that doesn't resolve
		// 4) bogus IP address (eg. 1154.218.100.183)
		log.Println("Could not log response: missing IP address")
		return
	}
	if ctx.Resp != nil {
		contentLength = ctx.Resp.ContentLength
	}
	from_host, from_port, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
	hostname := extractHostname(ctx)

	serviceName, serviceNameErr := conf.RoleFromRequest(ctx.Req)
	if serviceNameErr != nil {
		serviceName = ""
	}

	log.Printf("info: Completed response: "+
		"proxy_type=http known_role=%#v role=%#v src_host=%#v src_port=%s host=%#v dest_ip=%#v dest_port=%d start_time=%#v end_time=%d content_length=%#v\n",
		serviceNameErr == nil,
		serviceName,
		from_host,
		from_port,
		hostname,
		ctx.RoundTrip.TCPAddr.IP.String(),
		ctx.RoundTrip.TCPAddr.Port,
		ctx.UserData,
		time.Now().Unix(),
		// The content length is often -1 because of HTTP chunked encoding. this is normal.
		contentLength,
	)
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
	log.Println("info: Starting Smokescreen")
	proxy := buildProxy(config)

	listener, err := findListener(config.Ip, config.Port)
	if err != nil {
		log.Fatal(err)
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
		case <- kill:
			log.Printf("Closed socket.")

		case <- quit:
			semiGraceful = false
		}
		listener.Close()
	}()
	err := server.Serve(listener)
	if !strings.HasSuffix(err.Error(), "use of closed network connection") {
		log.Fatal(err)
	}

	if semiGraceful {
		// the program has exited normally, wait 60s in an attempt to shutdown
		// semi-gracefully
		log.Printf("Waiting %s before shutting down\n", config.ExitTimeout)
		time.Sleep(config.ExitTimeout)
	}
}

func checkIfRequestShouldBeProxied(config *Config, req *http.Request, outboundHost string) bool {
	fail := func(err error) bool {
		return false
	}

	if config.EgressAcl != nil {
		role, err := config.RoleFromRequest(req)
		if err != nil {
			return fail(err)
		}

		project := ""
		project, projectErr := config.EgressAcl.Project(role)

		result, err := config.EgressAcl.Decide(role, outboundHost)
		if err != nil {
			return fail(err)
		}
		switch result {
		case EgressAclDecisionDeny:
			log.Printf("critical: Request denied by ACL: " +
				"proxied=false known_project=%#v project=%#v role=%#v host=%#v",
				projectErr == nil, project, role, outboundHost)
		    return false

		case EgressAclDecisionAllowAndReport:
			log.Printf("warn: Request allowed and reported by ACL: " +
				"proxied=true known_project=%#v project=%#v role=%#v host=%#v\n",
				projectErr == nil, project, role, outboundHost)
		case EgressAclDecisionAllow:
			// Well, everything is going as expected.
		}
	}
	return true
}
