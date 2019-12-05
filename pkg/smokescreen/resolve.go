package smokescreen

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func resolveTCPAddr(r *net.Resolver, network, addr string) (*net.TCPAddr, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unknown network type %q", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resolvedPort, err := r.LookupPort(ctx, network, port)
	if err != nil {
		return nil, err
	}

	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) < 1 {
		return nil, fmt.Errorf("no IPs resolved")
	}

	return &net.TCPAddr{
		IP:   ips[0].IP,
		Zone: ips[0].Zone,
		Port: resolvedPort,
	}, nil
}

func safeResolve(config *Config, network, addr string) (*net.TCPAddr, string, error) {
	config.StatsdClient.Incr("resolver.attempts_total", []string{}, 1)
	resolved, err := resolveTCPAddr(config.Resolver, network, addr)
	if err != nil {
		config.StatsdClient.Incr("resolver.errors_total", []string{}, 1)
		return nil, "", err
	}

	classification := classifyAddr(config.AllowRanges, config.DenyRanges, resolved)
	config.StatsdClient.Incr(classification.statsdString(), []string{}, 1)

	if classification.IsAllowed() {
		return resolved, classification.String(), nil
	}
	return nil, "destination address was denied by rule, see error", denyError{fmt.Errorf("The destination address (%s) was denied by rule '%s'", resolved.IP, classification)}
}

// Build an address parsable by net.ResolveTCPAddr
func resolveParsableAddr(req *http.Request) string {
	remoteHost := req.Host
	if strings.LastIndex(remoteHost, ":") <= strings.LastIndex(remoteHost, "]") {
		switch req.URL.Scheme {
		case "http":
			remoteHost = net.JoinHostPort(remoteHost, "80")
		case "https":
			remoteHost = net.JoinHostPort(remoteHost, "443")
		default:
			remoteHost = net.JoinHostPort(remoteHost, "0")
		}
	}
	return remoteHost
}
