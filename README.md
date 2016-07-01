# Smokescreen
Smokescreen is a HTTP CONNECT proxy. It proxies most traffic from Stripe to the
external world (e.g., webhooks).

Smokescreen restricts which URLs it connects to: it resolves each domain name
that is requested and ensures that it is a publicly routable IP and not a
Stripe-internal IP. This prevents a class of attacks where, for instance, our
own webhooks infrastructure is used to scan Stripe's internal network.

Smokescreen also allows us to centralize egress from Stripe, allowing us to give
financial partners stable egress IP addresses and abstracting away the details
of which Stripe service is making the request.

## Dependencies

Smokescreen uses [govendor][govendor] to manage dependencies.  The
repo contains documentation, but some useful commands are reproduced
below:

- **Installing or updating govendor**: `go get -u
    github.com/kardianos/govendor` (ensure `$GOPATH/bin` is in your
    `$PATH`)
- **Adding or updating a dependency**: `govendor fetch
    github.com/path/to/dep`

WARNING: smokescreen is currently very sensitive to the specific
version of goproxy. We've had problems in the past with keepalive
connections under newer versions.

[govendor]: https://github.com/kardianos/govendor

# Contributors

 - Evan Broder
 - Andrew Dunham
 - Andreas Fuchs
 - Carl Jackson
