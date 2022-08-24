package normalize

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const portMin, portMax = 0, 65535

// HasPort returns true if the provided address does not include a port number.
func HasPort(s string) bool {
	return strings.LastIndex(s, "]") < strings.LastIndex(s, ":")
}

// NormalizePort converts `s` to int if it represents a valid TCP port.
func Port(s string) (port int, err error) {
	port, err = strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port number %q: %v", s, err)
	}
	if port < portMin || port > portMax {
		return 0, fmt.Errorf("invalid port number %d: must be between %d and %d", port, portMin, portMax)
	}
	return
}

// NormalizeHost returns normalized representation of host (Punycode for DNS
// names, standardized IP address representation).
//
// If forceFQDN is true, returned normalized domain name will include a trailing
// dot.
func Host(s string, forceFQDN bool) (string, error) {
	if ip := net.ParseIP(s); ip != nil {
		// IP addresses might have different but equivalent representations
		// (e.g., `2001:DB8::` and `2001:db8::` are the same address).
		// This function provides a consistent representation.
		return ip.String(), nil
	}
	// If it's not an IP address then it must be a domain name.
	// Convert it to Punycode it so that we deal only with with ASCII from now on.
	// This way we can find out whether the domain name is malformed.
	domain, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid domain '%v': %v", s, err)
	}
	if forceFQDN && !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return domain, nil
}

// NormalizeHostPort takes a colon-separated host and port and returns a
// normalized representation of host (Punycode for DNS names, standardized IP
// address representation) and a port number.
//
// `hostPort` string needs to conform to `authority-form` as defined by
// https://datatracker.ietf.org/doc/html/rfc7230#section-5.3.3. In particular,
// port is not optional and must be provided.
//
// If forceFQDN is true, returned normalized domain name will be an FQDN.
func HostPort(hostPort string, forceFQDN bool) (host string, port int, err error) {
	host, portString, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}
	host, err = Host(host, forceFQDN)
	if err != nil {
		return "", 0, err
	}
	port, err = Port(portString)
	if err != nil {
		return "", 0, err
	}
	return
}

// NormalizeHostWithOptionalPort returns host (as string) and port (as int)
// normalized with `normalizeHost` and `normalizePort`.
//
// `hostPort` is a bare host or a colon-separated (':') host name and port.
// If no port is specified, the `scheme` string is used to find the default
// port (https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3).
//
// If forceFQDN is true, returned normalized domain name will be an FQDN.
func HostWithOptionalPort(hostPort, scheme string, forceFQDN bool) (string, int, error) {
	var err error
	const noPort = -1
	host, port := hostPort, noPort

	// net.SplitHostPort() doesn't handle bare IPv6 addresses well so
	// handle that case first.
	if ip := net.ParseIP(hostPort); ip != nil && ip.To4() == nil {
		// IP addresses might have different but equivalent representations
		// (e.g., `2001:DB8::` and `2001:db8::` are the same address).
		// Let's make sure we use a consistent representation from now on.
		host = ip.String()
	} else if HasPort(hostPort) {
		// Extract host and port if both are provided.
		var portString string
		host, portString, err = net.SplitHostPort(hostPort)
		if err != nil {
			return "", noPort, err
		}
		port, err = Port(portString)
		if err != nil {
			return "", noPort, err
		}
	}

	if port == noPort {
		// Port was not provided so try to determine it based on scheme.
		port, err = net.LookupPort("tcp", scheme)
		if err != nil {
			return "", noPort, errors.New("unable to determine port for " + scheme)
		}
	}

	host, err = Host(host, forceFQDN)
	if err != nil {
		return "", noPort, err
	}

	return host, port, nil
}
