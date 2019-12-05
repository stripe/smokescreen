package smokescreen

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"github.com/stripe/go-einhorn/einhorn"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

const (
	denyMsgTmpl = "Egress proxying is denied to host '%s': %s."
)

type aclDecision struct {
	reason, role, project, outboundHost string
	resolvedAddr                        *net.TCPAddr
	allow                               bool
	enforceWouldDeny                    bool
}

type ctxUserData struct {
	start    time.Time
	decision *aclDecision
	traceId  string
}

const (
	errorHeader = "X-Smokescreen-Error"
	roleHeader  = "X-Smokescreen-Role"
	traceHeader = "X-Smokescreen-Trace-ID"
)

func dial(config *Config, network, addr string, userdata interface{}) (net.Conn, error) {
	var role, outboundHost, reason, traceId string
	var resolved *net.TCPAddr

	if v, ok := userdata.(*ctxUserData); ok {
		role = v.decision.role
		outboundHost = v.decision.outboundHost
		resolved = v.decision.resolvedAddr
		traceId = v.traceId
	}

	if resolved == nil || addr != outboundHost || network != "tcp" {
		var err error
		resolved, reason, err = safeResolve(config, network, addr)
		userdata.(*ctxUserData).decision.reason = reason
		if err != nil {
			if _, ok := err.(denyError); ok {
				config.Log.WithFields(
					logrus.Fields{
						"address": addr,
						"error":   err,
					}).Error("unexpected illegal address in dialer")
			}

			return nil, err
		}
	}

	config.StatsdClient.Incr("cn.atpt.total", []string{}, 1)
	conn, err := net.DialTimeout(network, resolved.String(), config.ConnectTimeout)

	if err != nil {
		config.StatsdClient.Incr("cn.atpt.fail.total", []string{}, 1)
		return nil, err
	} else {
		config.StatsdClient.Incr("cn.atpt.success.total", []string{}, 1)
		return config.ConnTracker.NewInstrumentedConn(conn, traceId, role, outboundHost), nil
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
		http.StatusProxyAuthRequired,
		msg+"\n")
	resp.Status = "Request Rejected by Proxy" // change the default status message
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
		userData := ctxUserData{time.Now(), nil, ""}
		ctx.UserData = &userData
		remoteHost := resolveParsableAddr(req)

		config.Log.WithFields(
			logrus.Fields{
				"source_ip":      req.RemoteAddr,
				"requested_host": req.Host,
				"url":            req.RequestURI,
				"trace_id":       req.Header.Get(traceHeader),
			}).Debug("received HTTP proxy request")

		decision, err := checkIfRequestShouldBeProxied(config, req, remoteHost)
		userData.decision = decision
		userData.traceId = req.Header.Get(traceHeader)

		req.Header.Del(roleHeader)
		req.Header.Del(traceHeader)

		if err != nil {
			ctx.Error = err
			return req, rejectResponse(req, config, err)
		}
		if !userData.decision.allow {
			return req, rejectResponse(req, config, denyError{errors.New(userData.decision.reason)})
		}

		// Proceed with proxying the request
		return req, nil
	})

	// Handle CONNECT proxy to TLS & other TCP protocols destination
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		ctx.UserData = &ctxUserData{time.Now(), nil, ""}
		defer ctx.Req.Header.Del(traceHeader)

		err := handleConnect(config, ctx)
		if err != nil {
			ctx.Resp = rejectResponse(ctx.Req, config, err)
			return goproxy.RejectConnect, ""
		}
		return goproxy.OkConnect, host
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil {
			resp.Header.Del(errorHeader)
		}

		if resp == nil && ctx.Error != nil {
			logrus.Warnf("rejecting with %#v", ctx.Error)
			return rejectResponse(ctx.Req, config, ctx.Error)
		}

		// In case of an error, this function is called a second time to filter the
		// response we generate so this logger will be called once.
		logHTTP(config, ctx)
		return resp
	})
	return proxy
}

func handleConnect(config *Config, ctx *goproxy.ProxyCtx) error {
	config.Log.WithFields(
		logrus.Fields{
			"remote":         ctx.Req.RemoteAddr,
			"requested_host": ctx.Req.Host,
			"trace_id":       ctx.Req.Header.Get(traceHeader),
		}).Debug("received CONNECT proxy request")
	start := time.Now()

	// Check if requesting role is allowed to talk to remote
	decision, err := checkIfRequestShouldBeProxied(config, ctx.Req, ctx.Req.Host)
	ctx.UserData.(*ctxUserData).decision = decision
	ctx.UserData.(*ctxUserData).traceId = ctx.Req.Header.Get(traceHeader)
	logProxy(config, ctx, "connect", decision.resolvedAddr, decision, ctx.Req.Header.Get(traceHeader), start, err)
	if err != nil {
		return err
	}
	if !decision.allow {
		return denyError{errors.New(decision.reason)}
	}

	return nil
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

	// Setup connection tracking
	config.ConnTracker = conntrack.NewTracker(config.IdleThreshold, config.StatsdClient, config.Log, config.ShuttingDown)

	server := http.Server{
		Handler: handler,
	}

	config.ShuttingDown.Store(false)
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
		exit := make(chan bool, 1)

		// This subroutine blocks until all connections close.
		go func() {
			config.Log.Print("Waiting for all connections to close...")
			config.ConnTracker.Wg.Wait()
			config.Log.Print("All connections are closed. Continuing with shutdown...")
			exit <- true
		}()

		// Sometimes, connections don't close and remain in the idle state. This subroutine
		// waits until all open connections are idle before sending the exit signal.
		go func() {
			config.Log.Print("Waiting for all connections to become idle...")
			beginTs := time.Now()
			for {
				checkAgainIn := config.ConnTracker.MaybeIdleIn()
				if checkAgainIn > 0 {
					if time.Now().Sub(beginTs) > config.ExitTimeout {
						config.Log.Print(fmt.Sprintf("Timed out at %v while waiting for all open connections to become idle.", config.ExitTimeout))
						exit <- true
						break
					} else {
						config.Log.Print(fmt.Sprintf("There are still active connections. Waiting %v before checking again.", checkAgainIn))
						time.Sleep(checkAgainIn)
					}
				} else {
					config.Log.Print("All connections are idle. Continuing with shutdown...")
					exit <- true
					break
				}
			}
		}()

		// Wait for the exit signal.
		<-exit
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

func checkIfRequestShouldBeProxied(config *Config, req *http.Request, outboundHost string) (*aclDecision, error) {
	decision := checkACLsForRequest(config, req, outboundHost)

	if decision.allow {
		resolved, reason, err := safeResolve(config, "tcp", outboundHost)
		if err != nil {
			if _, ok := err.(denyError); !ok {
				return decision, err
			}
			decision.reason = fmt.Sprintf("%s. %s", err.Error(), reason)
			decision.allow = false
			decision.enforceWouldDeny = true
		} else {
			decision.resolvedAddr = resolved
		}
	}

	return decision, nil
}

func checkACLsForRequest(config *Config, req *http.Request, outboundHost string) *aclDecision {
	decision := &aclDecision{
		outboundHost: outboundHost,
	}

	if config.EgressACL == nil {
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

	submatch := hostExtractRE.FindStringSubmatch(outboundHost)
	destination := submatch[1]

	aclDecision, err := config.EgressACL.Decide(role, destination)
	if err != nil {
		config.Log.WithFields(logrus.Fields{
			"error": err,
			"role":  role,
		}).Warn("EgressAcl.Decide returned an error.")

		config.StatsdClient.Incr("acl.decide_error", []string{}, 1)
		decision.reason = aclDecision.Reason
		return decision
	}

	tags := []string{
		fmt.Sprintf("role:%s", decision.role),
		fmt.Sprintf("def_rule:%t", aclDecision.Default),
		fmt.Sprintf("project:%s", aclDecision.Project),
	}

	decision.reason = aclDecision.Reason
	switch aclDecision.Result {
	case acl.Deny:
		decision.enforceWouldDeny = true
		config.StatsdClient.Incr("acl.deny", tags, 1)

	case acl.AllowAndReport:
		decision.enforceWouldDeny = true
		config.StatsdClient.Incr("acl.report", tags, 1)
		decision.allow = true

	case acl.Allow:
		// Well, everything is going as expected.
		decision.allow = true
		decision.enforceWouldDeny = false
		config.StatsdClient.Incr("acl.allow", tags, 1)
	default:
		config.Log.WithFields(logrus.Fields{
			"role":        role,
			"destination": destination,
			"action":      aclDecision.Result.String(),
		}).Warn("Unknown ACL action")
		decision.reason = "Internal error"
		config.StatsdClient.Incr("acl.unknown_error", tags, 1)
	}

	return decision
}
