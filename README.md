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

# Contributors

 - Evan Broder
 - Andrew Dunham
 - Andreas Fuchs
 - Carl Jackson
 - Aditya Mukerjee
