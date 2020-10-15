# Smokescreen [![Build Status](https://travis-ci.org/stripe/smokescreen.svg?branch=master)](https://travis-ci.org/stripe/smokescreen)

Smokescreen is an HTTP CONNECT proxy used to handle most outbound TCP
connections from Stripe's infrastructure to the Internet.  This allows Stripe
to centralize Internet egress in its infrastructure and give customers and
partners a small set of stable Internet-facing IP addresses to expect
connections from.

Smokescreen can restrict which hostnames or IP addresses a client can connect
to by determining the client's service role and using service-specific access
control lists (ACLs).  Smokescreen has built-in methods for identifying clients
based on client TLS certificates and HTTP request headers, but you can also
supply your own code to identify clients — see the "Client identification"
section below for details.

Additionally, Smokescreen restricts which IP addresses it will connect to by
ensuring that all requested hostnames resolve to public (globally-routable) IP
addresses, not private or internal addresses.  This prevents a class of attacks
where, for example, our webhook delivery infrastructure is used to scan our
internal networks.

Smokescreen supports directly accepting connections over TLS.  Additionally,
you can provide it with a set of client certificate authority (CA) certificates
and their CRLs to enable mutual TLS authentication (mTLS) with clients.
Smokescreen will warn you if you load a CA certificate with no associated CRL,
and it will abort if you try to load a CRL that cannot be used (e.g. the CTL
cannot be associated with a loaded CA certificate).

## Dependencies

Smokescreen is built and tested on the latest major release of Go, which is
currently Go 1.15.

Smokescreen uses [Go modules](https://github.com/golang/go/wiki/Modules) to
manage dependencies.

Smokescreen uses [a fork of goproxy](https://github.com/stripe/goproxy) to
support context passing and setting granular timeouts on proxy connections.

## Usage

### CLI

Here are the options you can give Smokescreen:

```
   --help                                      Show this help text.
   --config-file FILE                          Load configuration from FILE.  Command line options override values in the file.
   --listen-ip IP                              Listen on interface with address IP.
                                                 This argument is ignored when running under Einhorn. (default: any)
   --listen-port PORT                          Listen on port PORT.
                                                 This argument is ignored when running under Einhorn. (default: 4750)
   --timeout DURATION                          Time out after DURATION when connecting. (default: 10s)
   --proxy-protocol                            Enable PROXY protocol support.
   --deny-range RANGE                          Add RANGE(in CIDR notation) to list of blocked IP ranges.  Repeatable.
   --allow-range RANGE                         Add RANGE (in CIDR notation) to list of allowed IP ranges.  Repeatable.
   --deny-address value                        Add IP[:PORT] to list of blocked IPs.  Repeatable.
   --allow-address value                       Add IP[:PORT] to list of allowed IPs.  Repeatable.
   --egress-acl-file FILE                      Validate egress traffic against FILE
   --resolver-address ADDRESS                  Make DNS requests to ADDRESS (IP:port).  Repeatable.
   --statsd-address ADDRESS                    Send metrics to statsd at ADDRESS (IP:port). (default: "127.0.0.1:8200")
   --tls-server-bundle-file FILE               Authenticate to clients using key and certs from FILE
   --tls-client-ca-file FILE                   Validate client certificates using Certificate Authority from FILE
   --tls-crl-file FILE                         Verify validity of client certificates against Certificate Revocation List from FILE
   --additional-error-message-on-deny MESSAGE  Display MESSAGE in the HTTP response if proxying request is denied
   --disable-acl-policy-action POLICY ACTION   Disable usage of a POLICY ACTION such as "open" in the egress ACL
   --stats-socket-dir DIR                      Enable connection tracking. Will expose one UDS in DIR going by the name of "track-{pid}.sock".
                                                 This should be an absolute path with all symlinks, if any, resolved.
   --stats-socket-file-mode FILE_MODE          Set the filemode to FILE_MODE on the statistics socket (default: "700")
   --version, -v                               print the version
```

### Client identification

By default, Smokescreen identifies clients in the following manner:

| Client CA configured? | Method                                   |
| --------------------- | ---------------------------------------- |
| yes                   | client certificate's "common name" (CN)  |
| no                    | `X-Smokescreen-Role` HTTP request header |

In order to override how Smokescreen identifies clients, you must:

- Create a new Go project
- Import Smokescreen
- Create a Smokescreen configuration using `cmd.NewConfiguration`
- Replace `smokescreen.Config.RoleFromRequest` with your own `func(request *http.Request) (string, error)`
- Call `smokescreen.StartWithConfig`
- Build your new project and use the resulting executable through its CLI

Here is an example that splits a client certificate's "Organizational Unit"
(OU) on commas and uses the first part as the service name:

```go
package main

import (...)

func main() {
	// Here is an opportunity to pass your logger
	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	if conf == nil {
		os.Exit(1)
	}

	conf.RoleFromRequest = func(request *http.Request) (string, error) {
		fail := func(err error) (string, error) { return "", err }

		subject := request.TLS.PeerCertificates[0].Subject
		if len(subject.OrganizationalUnit) == 0 {
			fail(fmt.Errorf("warn: Provided cert has no 'OrganizationalUnit'. Can't extract service role."))
		}
		return strings.SplitN(subject.OrganizationalUnit[0], ".", 2)[0], nil
	}

	smokescreen.StartWithConfig(conf, nil)
}
```

### ACLs

Smokescreen's ACL is described in a YAML file.  At its top level, the ACL
contains a list of services and the default policy for services not explicitly
configured in the ACL.

Three policies are supported:

| Policy  | Behavior                                                                                                      |
| ------- | ------------------------------------------------------------------------------------------------------------- |
| Open    | Allow all traffic for this service                                                                            |
| Report  | Allow all traffic for this service but warn if the client requests a host that is not in the list             |
| Enforce | Only allow traffic to remote hosts provided in the list — warn and deny if the remote host is not in the list |

A host can be specified with or without a globbing prefix:

| host                | valid   |
| ------------------- | ------- |
| `example.com`       | yes     |
| `*.example.com`     | yes     |
| `api.*.example.com` | no      |
| `*example.com`      | no      |
| `ex*ample.com`      | no      |
| `example.*`         | no      |

[A sample ACL](https://github.com/stripe/smokescreen/blob/master/pkg/smokescreen/acl/v1/testdata/sample_config.yaml) is included in Smokescreen's tests.

#### Global allow/deny lists

Optionally, you may specify a global allow list and a global deny list in your
ACL config.  These lists override the policy but do not override the
`allowed_domains` list for each service.

For example, specifying `example.com` in your `global_allow_list` will allow
traffic for that domain on that role, even if that role is set to `enforce` and
does not specify `example.com` in its allowed domains.

Similarly, specifying `malicious.com` in your `global_deny_list` will deny
traffic for that domain on a role, even if that role is set to `report` or
`open`.  However, if a service also specifies `malicious.com` in its
`allowed_domains`, traffic to `malicious.com` will be allowed on that role,
regardless of policy.

If a domain matches both the `global_allow_list` and the `global_deny_list`,
the `global_deny_list` behavior takes priority.

[A sample ACL that uses global allow/deny lists](https://github.com/stripe/smokescreen/blob/master/pkg/smokescreen/acl/v1/testdata/sample_config_with_global.yaml)
is included in Smokescreen's tests.

# Contributors

 - Aditya Mukerjee
 - Andreas Fuchs
 - Andrew Dunham
 - Andrew Metcalf
 - Aniket Joshi
 - Carl Jackson
 - Craig Shannon
 - Evan Broder
 - Marc-André Tremblay
 - Richard Godbee
 - Ryan Koppenhaver
