package smokescreen

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/armon/go-proxyproto"
	"github.com/elazarl/goproxy"
	"github.com/stripe/go-einhorn/einhorn"
)

type ipType int

const (
	public ipType = iota
	private
	whitelisted
)

func (t ipType) String() string {
	switch t {
	case public:
		return "public"
	case private:
		return "private"
	case whitelisted:
		return "whitelisted"
	default:
		panic(fmt.Sprintf("unknown ip type %d", t))
	}
}

const errorHeader = "X-Smokescreen-Error"

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
	for _, net := range nets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func classifyIP(config *Config, ip net.IP) ipType {
	if isPrivateNetwork(config.PrivateNetworks, ip) {
		if isWhitelistNetwork(config.WhitelistNetworks, ip) {
			return whitelisted
		} else {
			return private
		}
	} else {
		return public
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
	case public:
		return resolved.String(), nil
	case whitelisted:
		config.StatsdClient.Count("resolver.private_whitelist_total", 1, []string{}, 0.3)
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

		return req, nil
	})
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		fail := func(err error) (*goproxy.ConnectAction, string) { return goproxy.RejectConnect, fmt.Sprint(err) }

		ctx.Logf("Received CONNECT proxy request: "+
			"remote=%#v host=%#v",
			ctx.Req.RemoteAddr,
			host)

		fmt.Printf("Host: %#v", host)
		fmt.Println(len(ctx.Req.TLS.PeerCertificates))

		resolved, err := safeResolve(config, "tcp", host)
		if err != nil {
			ctx.Resp = errorResponse(ctx.Req, err)
			return goproxy.RejectConnect, host
		}

		// Check if requesting service is allowed to talk to remote

		checkOutcome := checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.RemoteAddr)

		// todo: refactor this
		serviceName, _ := config.RoleFromRequest(ctx.Req)
		if err != nil {
			return fail(err)
		}
		switch checkOutcome {
		case EgressAclDecisionDeny:
			ctx.Logf("critical: Service '%s' tried to access host '%s'. Denied by ACL.", serviceName, host)
			return goproxy.RejectConnect, host

		case EgressAclDecisionAllowAndReport:
			ctx.Logf("info: Service '%s' tried to access host '%s'. ACL specifies ConfigEnforcementPolicyReport mode: traffic allowed.", serviceName, host)

		case EgressAclDecisionAllow:
			// Well, nothing special to be done in this case
		}

		ctx.UserData = time.Now().Unix()
		logHttpsRequest(ctx, resolved)
		return goproxy.OkConnect, resolved
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		logResponse(ctx)
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
	var hostname string
	if ctx.Req != nil {
		hostname, _, _ = net.SplitHostPort(ctx.Req.Host)
	}
	return hostname
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

func logResponse(ctx *goproxy.ProxyCtx) {
	var contentLength int64
	if ctx.RoundTrip == nil || ctx.RoundTrip.TCPAddr == nil {
		// Reasons this might happen:
		// 1) private ip destination (eg. 192.168.0.0/16, 10.0.0.0/8, etc)
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
	log.Printf("Completed response: "+
		"proxy_type=http src_host=%#v src_port=%s host=%#v dest_ip=%#v dest_port=%d start_time=%#v end_time=%d content_length=%#v\n",
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

func findListener(defaultPort int) (net.Listener, error) {
	if einhorn.IsWorker() {
		listener, err := einhorn.GetListener(0)
		if err != nil {
			return nil, err
		}

		err = einhorn.Ack()

		return listener, err
	} else {
		return net.Listen("tcp", fmt.Sprintf(":%d", defaultPort))
	}
}

func StartWithConfig(config *Config) {
	proxy := buildProxy(config)

	listener, err := findListener(config.Port)
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

	runServer(config, &server, listener)
}

func runServer(config *Config, server *http.Server, listener net.Listener) {
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
	kill := make(chan os.Signal, 1)

	signal.Notify(kill, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-kill
		listener.Close()
		log.Printf("Closed socket.")
	}()
	err := server.Serve(listener)
	if !strings.HasSuffix(err.Error(), "use of closed network connection") {
		log.Fatal(err)
	} else {
		// the program has exited normally, wait 60s in an attempt to shutdown
		// semi-gracefully
		log.Printf("Waiting %s before shutting down\n", config.ExitTimeout)
		time.Sleep(config.ExitTimeout)
	}
}

func checkIfRequestShouldBeProxied(config *Config, req *http.Request, outboundHost string) EgressAclDecision {
	fail := func(err error) EgressAclDecision {
		log.Printf("warn: %#v", err)
		return EgressAclDecisionDeny
	}

	if config.EgressAcl != nil {
		role, err := config.RoleFromRequest(req)
		if err != nil {
			return fail(err)
		}
		result, err := config.EgressAcl.Decide(role, outboundHost)
		if err != nil {
			return EgressAclDecisionDeny
		}
		return result
	}
	return EgressAclDecisionAllow
}
