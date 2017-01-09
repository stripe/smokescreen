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
	"github.com/icub3d/graceful"
	"github.com/stripe/go-einhorn/einhorn"
	"gopkg.in/elazarl/goproxy.v1"
)

var privateNetworks []net.IPNet

var connectTimeout time.Duration

var track *statsd.Client

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

func safeResolve(network, addr string) (string, error) {
	track.Count("resolver.attempts_total", 1, []string{}, 0.3)
	resolved, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		track.Count("resolver.errors_total", 1, []string{}, 0.3)
		return "", err
	}

	if isPrivateNetwork(resolved.IP) {
		track.Count("resolver.illegal_total", 1, []string{}, 0.3)
		return "", fmt.Errorf("host %s resolves to illegal IP %s",
			addr, resolved.IP)
	}

	return resolved.String(), nil
}

func dial(network, addr string) (net.Conn, error) {
	resolved, err := safeResolve(network, addr)
	if err != nil {
		return nil, err
	}

	return net.DialTimeout(network, resolved, connectTimeout)
}

func errorResponse(req *http.Request, err error) *http.Response {
	resp := goproxy.NewResponse(req,
		goproxy.ContentTypeText,
		http.StatusServiceUnavailable,
		err.Error()+"\n")
	resp.ProtoMajor = req.ProtoMajor
	resp.ProtoMinor = req.ProtoMinor
	resp.Header.Add("X-Smokescreen-Error", err.Error())
	return resp
}

func buildProxy() *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Tr.Dial = dial
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
		ctx.Logf("Received CONNECT proxy request: "+
			"remote=%#v host=%#v",
			ctx.Req.RemoteAddr,
			host)

		resolved, err := safeResolve("tcp", host)
		if err != nil {
			ctx.Resp = errorResponse(ctx.Req, err)
			return goproxy.RejectConnect, ""
		}
		ctx.UserData = time.Now().Unix()
		return goproxy.OkConnect, resolved
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		logResponse(ctx)
		if resp == nil && ctx.Error != nil {
			resp = errorResponse(ctx.Req, ctx.Error)
		}
		return resp
	})

	return proxy
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
	log.Printf("Completed response: "+
		"src_host=%#v src_port=%s host=%#v dest_ip=%#v dest_port=%d start_time=%#v end_time=%d content_length=%#v\n",
		from_host,
		from_port,
		ctx.Req.Host,
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

	flag.IntVar(&port, "port", 4750, "Port to bind on")
	flag.DurationVar(&connectTimeout, "timeout",
		time.Duration(10)*time.Second, "Time to wait while connecting")
	flag.StringVar(&maintenanceFile, "maintenance", "",
		"Flag file for maintenance. chmod to 000 to put into maintenance mode")
	flag.Parse()

	proxy := buildProxy()

	listener, err := findListener(port)
	if err != nil {
		log.Fatal(err)
	}

	kill := make(chan os.Signal, 1)

	var handler http.Handler = proxy
	if maintenanceFile != "" {
		handler = &HealthcheckMiddleware{
			App:             handler,
			MaintenanceFile: maintenanceFile,
		}
	}

	server := graceful.NewServer(&http.Server{
		Handler: handler,
	})
	go func() {
		<-kill
		server.Close()
	}()
	signal.Notify(kill, syscall.SIGUSR2, syscall.SIGTERM)

	err = server.Serve(listener)
	if !strings.HasSuffix(err.Error(), "use of closed network connection") {
		log.Fatal(err)
	}
}
