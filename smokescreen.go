package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/armon/go-proxyproto"
	"github.com/elazarl/goproxy"
	"github.com/stripe/go-einhorn/einhorn"
)

var privateNetworks []net.IPNet

var connectTimeout time.Duration

var track *statsd.Client

const exitTimeout = 60 * time.Second

const errorHeader = "X-Smokescreen-Error"

func init() {
	var err error
	privateNetworkStrings := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}

	privateNetworks = make([]net.IPNet, len(privateNetworkStrings))
	for i, netstring := range privateNetworkStrings {
		_, net, err := net.ParseCIDR(netstring)
		if err != nil {
			log.Fatal(err)
		}
		privateNetworks[i] = *net
	}

	track, err = statsd.New("127.0.0.1:8200")
	if err != nil {
		log.Fatal(err)
	}
	track.Namespace = "smokescreen."
}

func isPrivateNetwork(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return true
	}

	for _, net := range privateNetworks {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func safeResolve(network, addr, remoteAddr string, allowPrivate bool) (string, error) {
	track.Count("resolver.attempts_total", 1, []string{}, 0.3)
	resolved, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		track.Count("resolver.errors_total", 1, []string{}, 0.3)
		return "", err
	}

	tags := []string{
		fmt.Sprintf("network:%s", network),
		fmt.Sprintf("addr:%s", addr),
		fmt.Sprintf("remote_addr:%s", remoteAddr),
	}
	if isPrivateNetwork(resolved.IP) {
		// even if we're allowing private addresses, we still don't want to proxy
		// requests to localhost, or to the ec2 metadata service, or whatever
		if allowPrivate && resolved.IP.IsGlobalUnicast() {
			track.Count("resolver.allowed_private_address", 1, tags, 1.0)
		} else {
			track.Count("resolver.illegal_total", 1, tags, 1.0)
			return "", fmt.Errorf("host %s resolves to illegal IP %s",
				addr, resolved.IP)
		}
	}

	return resolved.String(), nil
}

func makeDial(allowPrivate bool) func(string, string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		resolved, err := safeResolve(network, addr, "unknown", allowPrivate)
		if err != nil {
			return nil, err
		}

		return net.DialTimeout(network, resolved, connectTimeout)
	}
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

func buildProxy(allowPrivate bool) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Tr.Dial = makeDial(allowPrivate)
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
		remoteAddr := ctx.Req.RemoteAddr
		ctx.Logf("Received CONNECT proxy request: "+
			"remote=%#v host=%#v",
			remoteAddr,
			host)

		resolved, err := safeResolve("tcp", host, remoteAddr, allowPrivate)
		if err != nil {
			ctx.Resp = errorResponse(ctx.Req, err)
			return goproxy.RejectConnect, ""
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

func main() {
	var port int
	var maintenanceFile string
	var proxyProto bool
	var allowPrivate bool

	flag.IntVar(&port, "port", 4750, "Port to bind on")
	flag.DurationVar(&connectTimeout, "timeout",
		time.Duration(10)*time.Second, "Time to wait while connecting")
	flag.StringVar(&maintenanceFile, "maintenance", "",
		"Flag file for maintenance. chmod to 000 to put into maintenance mode")
	flag.BoolVar(&proxyProto, "proxy-protocol", false, "Enables PROXY protocol support")
	flag.BoolVar(&allowPrivate, "allow-private", false, "Allow proxying to private addresses")
	flag.Parse()

	proxy := buildProxy(allowPrivate)

	listener, err := findListener(port)
	if err != nil {
		log.Fatal(err)
	}

	if proxyProto {
		listener = &proxyproto.Listener{Listener: listener}
	}

	var handler http.Handler = proxy
	if maintenanceFile != "" {
		handler = &HealthcheckMiddleware{
			App:             handler,
			MaintenanceFile: maintenanceFile,
		}
	}

	server := http.Server{
		Handler: handler,
	}

	runServer(&server, listener)
}

func runServer(server *http.Server, listener net.Listener) {
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
		log.Printf("Waiting %s before shutting down\n", exitTimeout)
		time.Sleep(exitTimeout)
	}
}
