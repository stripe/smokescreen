package hostport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const portMin, portMax = 0, 65535
const NoPort = -1

type HostPort struct {
	Host string
	Port int
}

func (hp HostPort) IsIP() bool {
	return net.ParseIP(hp.Host) != nil
}

func (hp HostPort) IsFQDN() bool {
	return hp.IsIP() || strings.HasSuffix(hp.Host, ".")
}

func (hp HostPort) FQDN() string {
	if hp.Host != "" && !hp.IsFQDN() {
		return hp.Host + "."
	}
	return hp.Host
}

func (hp HostPort) String() string {
	if hp.Host != "" && hp.Port != NoPort {
		return net.JoinHostPort(hp.Host, strconv.Itoa(hp.Port))
	}
	return ""
}

// New takes a colon-separated host and port and returns a normalized
// representation of host (Punycode for DNS names, standardized IP address
// representation) and a port number.
//
// `s` argument needs to conform to `authority-form` as defined by
// https://datatracker.ietf.org/doc/html/rfc7230#section-5.3.3. In particular,
// port must be provided.
//
// If forceFQDN is true, returned normalized domain name will be an FQDN.
func New(s string, forceFQDN bool) (hostport HostPort, err error) {
	hostport.Port = NoPort

	var portString string
	hostport.Host, portString, err = net.SplitHostPort(s)
	if err != nil {
		return
	}
	hostport.Host, err = NormalizeHost(hostport.Host, forceFQDN)
	if err != nil {
		return
	}
	hostport.Port, err = NormalizePort(portString)
	return
}

// NewWithScheme returns host (as string) and port (as int)
// normalized with `normalizeHost` and `normalizePort`.
//
// `s` is a bare host or a colon-separated (':') host name and port.
// If no port is specified, the `scheme` string is used to find the default
// port (https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3).
//
// If forceFQDN is true, returned normalized domain name will be an FQDN.
func NewWithScheme(s, scheme string, forceFQDN bool) (hostport HostPort, err error) {
	hostport.Port = NoPort

	// net.SplitHostPort() doesn't handle bare IPv6 addresses well so
	// handle that case first.
	if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
		// IP addresses might have different but equivalent representations
		// (e.g., `2001:DB8::` and `2001:db8::` are the same address).
		// Let's make sure we use a consistent representation from now on.
		hostport.Host = ip.String()
	} else if HasPort(s) {
		// Extract host and port if both are provided.
		var portString string
		hostport.Host, portString, err = net.SplitHostPort(s)
		if err != nil {
			return
		}
		hostport.Port, err = NormalizePort(portString)
		if err != nil {
			return
		}
	} else {
		hostport.Host = s
	}

	if hostport.Port == NoPort {
		// Port was not provided so try to determine it based on scheme.
		hostport.Port, err = net.LookupPort("tcp", scheme)
		if err != nil {
			hostport.Port = NoPort
			err = errors.New("unable to determine port for " + scheme)
			return
		}
	}

	hostport.Host, err = NormalizeHost(hostport.Host, forceFQDN)
	return
}

// HasPort returns true if the provided address does not include a port number.
func HasPort(s string) bool {
	return strings.LastIndex(s, "]") < strings.LastIndex(s, ":")
}

// NormalizeHost returns normalized representation of host (Punycode for DNS
// names, standardized IP address representation).
//
// If forceFQDN is true, returned normalized domain name will include a trailing
// dot.
func NormalizeHost(s string, forceFQDN bool) (string, error) {
	if ip := net.ParseIP(s); ip != nil {
		// IP addresses might have different but equivalent representations
		// (e.g., `2001:DB8::` and `2001:db8::` are the same address).
		// This function provides a consistent representation.
		return ip.String(), nil
	}
	// If it's not an IP address then it must be a domain name.
	//
	// [idna]'s Lookup profile does not accept underscores (`_`) in domain names,
	// an RFC violation that is unfortunately too common.
	//
	// Since there is no way to customize the Lookup profile, it needs to be
	// recreated here while keeping in mind that the upstream's version is
	// subject to change. Based on:
	// https://cs.opensource.google/go/x/net/+/b0a4917e:idna/idna10.0.0.go;l=286-295
	idnaProfile := idna.New(
		idna.MapForLookup(),
		idna.BidiRule(),
		idna.StrictDomainName(false), // Intended diversion from idna.Lookup profile.
	)
	// Convert it to Punycode it so that we deal only with with ASCII from now on.
	// This way we can also find out whether the domain name is malformed.
	domain, err := idnaProfile.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", s, err)
	}

	// Given that DNS is not case sensitive, let's use the lowercase form.
	domain = strings.ToLower(domain)

	// Since we disable StrictDomainName() checks, apply our own more lenient checks.
	// The permittable set of characters is identical to the one defined by
	// [RFC 1034] with the notable addition of an underscore (`_`) due to its
	// widespread use.
	//
	// [RFC 1034]: https://tools.ietf.org/html/rfc1034
	const validDNSCharacters = "abcdefghijklmnopqrstuvwxyz0123456789.-_"
	if invalid := strings.Trim(domain, validDNSCharacters); len(invalid) > 0 {
		return domain, fmt.Errorf("invalid domain %q: disallowed rune %U", s, invalid[0])
	}
	if forceFQDN && domain != "" && !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return strings.ToLower(domain), nil
}

// NormalizePort converts `s` to int if it represents a valid TCP port.
func NormalizePort(s string) (port int, err error) {
	port, err = strconv.Atoi(s)
	if err != nil {
		return NoPort, fmt.Errorf("invalid port number %q: %w", s, err)
	}
	if port < portMin || port > portMax {
		return NoPort, fmt.Errorf("invalid port number %d: must be between %d and %d", port, portMin, portMax)
	}
	return
}
