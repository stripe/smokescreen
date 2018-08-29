# Smokescreen [![Build Status](https://travis-ci.org/stripe/smokescreen.svg?branch=master)](https://travis-ci.org/stripe/smokescreen)
Smokescreen is a HTTP CONNECT proxy. It proxies most traffic from Stripe to the
external world (e.g., webhooks).

Smokescreen restricts which URLs it connects to: it resolves each domain name
that is requested and ensures that it is a publicly routable IP and not a
Stripe-internal IP. This prevents a class of attacks where, for instance, our
own webhooks infrastructure is used to scan Stripe's internal network.

Smokescreen also allows us to centralize egress from Stripe, allowing us to give
financial partners stable egress IP addresses and abstracting away the details
of which Stripe service is making the request.

Smokescreen can be contacted over TLS. You can provide it with one or more client certificate authority certificates as well as their CRLs.
Smokescreen will warn you if you load a CA certificate with no associated CRL and will abort if you try to load a CRL which cannot be used (ex.: cannot be associated with loaded CA).

Smokescreen can be provided with an ACL to determine which remote hosts a service is allowed to interact with.
By default, Smokescreen will identify the clients in the following manner:

| client ca provided? | method |
| --- | --- |
| yes | client cert's `common name` |
| no | `X-Smokescreen-Role` header |

The client identification function can also be replaced by one of your liking. More on this in the usage section.

## Dependencies

Smokescreen uses [dep][dep] to manage dependencies.  The
repo contains documentation, but some useful commands are reproduced
below:

- **Installing or updating dep**: `go get -u
    github.com/golang/dep/cmd/dep` (ensure `$GOPATH/bin` is in your
    `$PATH`)
- **Adding a dependency**: `dep ensure`
- **Updating a dependency**: `dep ensure -update`

Smokescreen uses a [custom fork](https://github.com/stripe/goproxy) of goproxy to avoid problems with keepalive connections present under newer versions of the upstream project.

[dep]: https://github.com/golang/dep


## Usage

### CLI
Here are the options you can give Smokescreen:
```
   --help                                     Show this help text.
   --listen-ip IP                             listen on interface with address IP.
                                                This argument is ignored when running under Einhorn. (default: any)
   --listen-port PORT                         listen on port PORT.
                                                This argument is ignored when running under Einhorn. (default: 4750)
   --timeout DURATION                         Time out after DURATION when connecting. (default: 10s)
   --maintenance-file FILE                    Watch FILE for maintenance mode.
                                                HTTP(S) requests to /healthcheck return 404 if the file's permissions are set to 000.
   --proxy-protocol                           Enable PROXY protocol support.
   --deny-range RANGE                         Add RANGE(in CIDR notation) to list of blocked IP ranges.  Repeatable.
   --allow-range RANGE                        Add RANGE (in CIDR notation) to list of allowed IP ranges.  Repeatable.
   --egress-acl-file FILE                     Validate egress traffic against FILE
   --statsd-address ADDRESS                   Send metrics to statsd at ADDRESS (IP:port). (default: "127.0.0.1:8200")
   --tls-server-bundle-file FILE              Authenticate to clients using key and certs from FILE
   --tls-client-ca-file FILE                  Validate client certificates using Certificate Authority from FILE
   --tls-crl-file FILE                        Verify validity of client certificates against Certificate Revocation List from FILE
   --danger-allow-access-to-private-ranges    WARNING: circumvent the check preventing client to reach hosts in private networks - It will make you vulnerable to SSRF.
   --additional-error-message-on-deny MESSAGE Display MESSAGE in the HTTP response if proxying request is denied
   --disable-acl-policy-action POLICY ACTION  Disable usage of a POLICY ACTION such as "open" in the egress ACL
   --version, -v                              print the version
```

### Importing
In order to override how Smokescreen identifies its clients, you must:
- Create a new go project
- Import Smokescreen
- Create a Smokescreen configuration using cmd.NewConfiguration
- Replace `smokescreen.Config.RoleFromRequest` with your own `func(request *http.Request) (string, error)`
- Call smokescreen.StartWithConfig
- Build your new project and use the resulting executable through its CLI

Here is a fictional example that would split a client certificate's `OrganizationalUnit` on commas and use the first particle as the service name.
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
An ACL can be described in a YAML formatted file. The ACL, at its top-level, contains a list of services as well as a default behavior.

Three policies are supported:

| Policy | Behavior |
| --- | --- |
| Open | Allows all traffic for this service |
| Report | Allows all traffic for this service and warns if client accesses a remote host which is not in the list | 
| Enforce | Only allows traffic to remote hosts provided in the list. Will warn and deny if remote host is not in the list |

A host can be specified with or without a globbing prefix

| host | valid |
| --- | --- |
| `example.com` | yes |
| `*.example.com` | yes |
| `api.*.example.com` | no | 
| `*example.com` | no |
| `ex*ample.com` | no |
| `example.*` | hell no |

[Here](https://github.com/stripe/smokescreen/blob/master/pkg/smokescreen/testdata/sample_config.yaml) is a sample ACL.

# Contributors

 - Evan Broder
 - Andrew Dunham
 - Andreas Fuchs
 - Carl Jackson
 - Aditya Mukerjee
 - Ryan Koppenhaver
 - Marc-André Tremblay
