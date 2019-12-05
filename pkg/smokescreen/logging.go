package smokescreen

import (
	"net"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
)

const (
	LOGLINE_CANONICAL_PROXY_DECISION = "CANONICAL-PROXY-DECISION"
)

func logProxy(
	config *Config,
	ctx *goproxy.ProxyCtx,
	proxyType string,
	toAddress *net.TCPAddr,
	decision *aclDecision,
	traceID string,
	start time.Time,
	err error,
) {
	var contentLength int64
	if ctx.Resp != nil {
		contentLength = ctx.Resp.ContentLength
	}

	fromHost, fromPort, _ := net.SplitHostPort(ctx.Req.RemoteAddr)

	fields := logrus.Fields{
		"proxy_type":     proxyType,
		"src_host":       fromHost,
		"src_port":       fromPort,
		"requested_host": ctx.Req.Host,
		"start_time":     start.Unix(),
		"content_length": contentLength,
		"trace_id":       traceID,
	}

	if toAddress != nil {
		fields["dest_ip"] = toAddress.IP.String()
		fields["dest_port"] = toAddress.Port
	}

	// attempt to retrieve information about the host originating the proxy request
	fields["src_host_common_name"] = "unknown"
	fields["src_host_organization_unit"] = "unknown"
	if ctx.Req.TLS != nil && len(ctx.Req.TLS.PeerCertificates) > 0 {
		fields["src_host_common_name"] = ctx.Req.TLS.PeerCertificates[0].Subject.CommonName
		var ou_entries = ctx.Req.TLS.PeerCertificates[0].Subject.OrganizationalUnit
		if ou_entries != nil && len(ou_entries) > 0 {
			fields["src_host_organization_unit"] = ou_entries[0]
		}
	}

	if decision != nil {
		fields["role"] = decision.role
		fields["project"] = decision.project
		fields["decision_reason"] = decision.reason
		fields["enforce_would_deny"] = decision.enforceWouldDeny
		fields["allow"] = decision.allow
	}

	if err != nil {
		fields["error"] = err.Error()
	}

	entry := config.Log.WithFields(fields)
	var logMethod func(...interface{})
	if _, ok := err.(denyError); !ok && err != nil {
		logMethod = entry.Error
	} else if decision != nil && decision.allow {
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

	logProxy(config, ctx, "http", toAddr, userData.decision, userData.traceId, userData.start, ctx.Error)
}

// From https://github.com/sirupsen/logrus/issues/436
type Log2LogrusWriter struct {
	Entry *logrus.Entry
}

func (w *Log2LogrusWriter) Write(b []byte) (int, error) {
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	w.Entry.Warning(string(b))
	return n, nil
}
