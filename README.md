# Smokescreen [![Test](https://github.com/stripe/smokescreen/actions/workflows/test.yml/badge.svg?branch=master&event=push)](https://github.com/stripe/smokescreen/actions/workflows/test.yml?query=branch%3Amaster) [![Coverage Status](https://coveralls.io/repos/github/stripe/smokescreen/badge.svg?branch=master)](https://coveralls.io/github/stripe/smokescreen?branch=master)

## Which version to use

> [!WARNING]
> **v2 is an early release, and it has no release tag yet.** Stripe uses v2 internally, but the first tagged v2 release will have breaking API changes. If you need a stable Go API, use v1 for now.

|                | v1                                                        | v2                                         |
| -------------- | --------------------------------------------------------- | ------------------------------------------ |
| Branch         | [`v1`](https://github.com/stripe/smokescreen/tree/v1)     | `master`                                   |
| Go module      | `github.com/stripe/smokescreen`                           | `github.com/stripe/smokescreen/v2`         |
| Release tags   | `v0.x.y`, for example `v0.1.0`                            | None yet. v2 is untagged: use the latest `master` commit, for example with `go get github.com/stripe/smokescreen/v2@master` |
| What it gets   | Security fixes, major bug fixes and dependency updates, for now | New features, security fixes and major bug fixes |

**Risks of using v2 now:**

- The Go API will change in the first tagged v2 release. Plan for code changes when you upgrade.
- v2 is new, so it has had less testing than v1.
- v2 changes some defaults and the way ACLs make decisions. Read [Migrating to v2](docs/migrating-to-v2.md) before you upgrade.

We fix security issues and major bugs in both v1 and v2.

Smokescreen is a HTTP CONNECT proxy. It proxies most traffic from Stripe to the
external world (e.g., webhooks).

Smokescreen restricts which URLs it connects to:
- It uses a pre-configured hostname ACL to only allow requests addressed to certain allow-listed hostnames,
to ensure that no malicious code is attempting to make requests to unexpected services.
- It also resolves each domain name that is requested, and ensures that it is a publicly routable
IP address and not an internal IP address. This prevents a class of attacks where, for instance,
our own webhooks infrastructure is used to scan Stripe’s internal network. Smokescreen
can also be further configured to allow or deny specific IP addresses or ranges.

Smokescreen also allows us to centralize egress from Stripe, allowing us to give
financial partners stable egress IP addresses and abstracting away the details
of which Stripe service is making the request.

In typical usage, clients contact Smokescreen over mTLS. Upon receiving a
connection, Smokescreen authenticates the client's certificate against a
configurable set of CAs and CRLs, extracts the client's identity, and checks
the client's requested CONNECT destination against a configurable per-client
ACL.

By default, Smokescreen will identify clients by the "common name" in the TLS
certificate they present, if any. The client identification function can also
be easily replaced; more on this in the usage section.

## Dependencies

Smokescreen uses [go modules][mod] to manage dependencies. The
linked page contains documentation, but some useful commands are reproduced
below:

- **Adding a dependency**: `go build` `go test` `go mod tidy` will automatically fetch the latest version of any new dependencies. Running `go mod vendor` will vendor the dependency.
- **Updating a dependency**: `go get dep@v1.1.1` or `go get dep@commit-hash` will bring in specific versions of a dependency. The updated dependency should be vendored using `go mod vendor`.

Smokescreen uses a [custom fork](https://github.com/stripe/goproxy) of goproxy to allow us to support context passing and setting granular timeouts on proxy connections.

Generally, Smokescreen will only support the two most recent Go versions. See
[the test configuration](.github/workflows/test.yml) for details.

### Building without Prometheus

Prometheus support is included by default:

```sh
go build .
```

> **Note:** Prometheus is currently opt-out. In a future release, it will become
> opt-in; consumers that require Prometheus should account for that build change.

To build a binary without Prometheus packages in its compiled dependency graph,
pass the `smokescreen_no_prometheus` build tag:

```sh
go build -tags=smokescreen_no_prometheus .
```

The no-Prometheus binary accepts the usual non-Prometheus configuration, but
fails during startup configuration if `--expose-prometheus-metrics` is set.

[mod]: https://github.com/golang/go/wiki/Modules

## Usage

### CLI

Run `go run . --help` (or `smokescreen --help` for an installed binary) for the
current CLI reference. Here are the available options:

```
   --help, -h                                  Show this help text.
   --config-file FILE                          Load configuration from FILE.  Command line options override values in the file.
   --listen-ip IP                              Listen on interface with address IP.
                                                 This argument is ignored when running under Einhorn. (default: any)
   --listen-port PORT                          Listen on port PORT.
                                                 This argument is ignored when running under Einhorn. (default: 4750)
   --timeout DURATION                          Time out after DURATION when connecting. (default: 10s)
   --proxy-protocol                            Enable PROXY protocol support.
   --allow-self-connections                    Allow connections to local interface addresses on all ports, subject to normal IP and ACL checks. (default: false)
   --most-specific-ip-rules                    Resolve overlapping IP rules by longest prefix, then port specificity; deny wins ties. (default: false)
   --unsafe-ip-filter-bypassed-domain DOMAIN    Bypass IP filters for a destination hostname or *.domain glob. Repeatable.
                                                 ACL and self-connection checks still apply. Trust this domain's DNS.
   --deny-range RANGE                          Add RANGE(in CIDR notation) to list of blocked IP ranges.  Repeatable.
   --allow-range RANGE                         Add RANGE (in CIDR notation) to list of allowed IP ranges.  Repeatable.
   --deny-address value                        Add IP[:PORT] to list of blocked IPs.  Repeatable.
   --allow-address value                       Add IP[:PORT] to list of allowed IPs.  Repeatable.
   --egress-acl-file FILE                      Validate egress traffic against FILE
   --expose-prometheus-metrics                 Exposes metrics via a Prometheus scrapable endpoint.
   --prometheus-metrics-format FORMAT          Metric format: legacy, dual, or v2. (default: "legacy")
                                                 Requires `--expose-prometheus-metrics` to be set.
   --prometheus-endpoint ENDPOINT              Specify endpoint to host Prometheus metrics on. (default: "/metrics")
                                                 Requires `--expose-prometheus-metrics` to be set.
   --prometheus-listen-ip IP                   Listen for Prometheus metrics on interface with address IP. (default: "127.0.0.1")
                                                 Requires `--expose-prometheus-metrics` to be set.
   --prometheus-port PORT                      Specify port to host Prometheus metrics on. (default: "9810")
                                                 Requires `--expose-prometheus-metrics` to be set.
   --resolver-address ADDRESS                  Make DNS requests to ADDRESS (IP:port). Repeatable. Each DNS exchange
                                                 picks an address at random.
   --statsd-address ADDRESS                    Send metrics to statsd at ADDRESS (IP:port). (default: "127.0.0.1:8200")
   --metric-tag KEY=VALUE                      Add a default tag to every metric. Repeatable; replaces metrics_tags from --config-file.
   --tls-server-bundle-file FILE               Authenticate to clients using key and certs from FILE
   --tls-client-ca-file FILE                   Validate client certificates using Certificate Authority from FILE
   --tls-crl-file FILE                         Verify validity of client certificates against Certificate Revocation List from FILE
   --additional-error-message-on-deny MESSAGE  Display MESSAGE in the HTTP response if proxying request is denied
   --disable-acl-policy-action POLICY ACTION   Disable usage of a POLICY ACTION such as "open" in the egress ACL
   --acl-compat                                Let service allow entries win over global.deny without override_global_policy, and warn (default: false)
   --acl-allow-unknown-fields                  Ignore ACL keys that the v2 format does not define, so the file can carry keys for other tools (default: false)
   --stats-socket-dir DIR                      Enable connection tracking. Will expose one UDS in DIR going by the name of "track-{pid}.sock".
                                                 This should be an absolute path with all symlinks, if any, resolved.
   --stats-socket-file-mode FILE_MODE          Set the filemode to FILE_MODE on the statistics socket (default: "700")
   --unsafe-allow-private-ranges               Allow private IP ranges by default. (default: false)
   --upstream-http-proxy-addr ADDRESS           Set Smokescreen's upstream HTTP proxy address.
   --upstream-https-proxy-addr ADDRESS          Set Smokescreen's upstream HTTPS proxy address.
   --max-concurrent-requests value             Maximum simultaneous requests. 0 = unlimited (default: 0)
   --max-request-rate value                    Maximum requests per second. 0 = unlimited (default: 0)
   --max-request-burst value                   Maximum burst capacity. Must be > max-request-rate when specified.
                                                 Omit to use default (2x max-request-rate).
   --max-concurrent-connect-tunnels value      Maximum number of concurrent CONNECT tunnels.
                                                 Unlike max-concurrent-requests, this limits actual long-lived connections.
                                                 0 = unlimited (default: 0)
   --dns-timeout DURATION                      Maximum time to wait for DNS resolution (default: 5s)
   --version, -v                               print the version
```

### Configuration files

Load the main YAML configuration with `--config-file`. Explicit CLI options
override values in the file. Unknown YAML fields are rejected. YAML names can
differ from CLI flags: for example, `--listen-ip` maps to `ip`,
`--listen-port` to `port`, `--timeout` to `connect_timeout`, and
`--egress-acl-file` to `acl_file`. The main configuration and hostname ACL are
separate files; the ACL has its own `version`, `services`, and `default` fields.

```yaml
ip: "127.0.0.1"
port: 4750
connect_timeout: 10s
acl_file: "acl.yaml"
metrics_tags:
  environment: production
  region: eu-west-1
```

See the [YAML configuration fields](pkg/smokescreen/config_loader.go) for supported
keys and [Development.md](Development.md) for complete local examples. Prometheus
and upstream proxy settings are configured through CLI flags or the Go API;
the main YAML loader does not accept them.

### Prometheus metrics

Enable scraping with `--expose-prometheus-metrics`. The metrics listener defaults
to `127.0.0.1:9810` with path `/metrics`, independently of the proxy's listen
address. Use `--prometheus-listen-ip`, `--prometheus-port`, and
`--prometheus-endpoint` to change the bind address, port, or path. To expose
metrics on every interface (for example when a scraper runs outside the host),
set an explicit listen address:

```sh
smokescreen --expose-prometheus-metrics --prometheus-listen-ip=0.0.0.0
```

Select the format with `--prometheus-metrics-format=legacy|dual|v2`:

- `legacy` (default) preserves existing names, units, and histogram buckets.
- `v2` uses the `smokescreen_` prefix, seconds for timings, and appropriate byte
  and connection-duration buckets. See the
  [metric definitions](pkg/smokescreen/metrics/metric_definitions.go) for mappings.
- `dual` publishes both formats so you can deploy first and migrate your observability
  stack later.

Embedded users can pass `"dual"` or `"v2"` as the optional final argument to `SetupPrometheus` or
`NewPrometheusMetricsClient`.

### Global metric tags

Use repeatable `--metric-tag` flags to set global defaults:

```sh
smokescreen --metric-tag environment=production --metric-tag region=eu-west-1
```

Or set `metrics_tags` in YAML above. CLI tags replace the YAML map; repeated keys
use their last value. Per-metric and per-emission tags override global defaults.

Go embedders can call `Config.SetGlobalMetricTags` before startup.

### Client Identification

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

### Logging

Smokescreen uses `log/slog`, with JSON output to stderr at INFO level by default.
Supply your own backend through any standard `slog.Handler`:

```go
cfg := smokescreen.NewConfig()
cfg.Log = slog.New(callerHandler)
```

For stock text output, use `slog.New(slog.NewTextHandler(w, nil))` instead.
For YAML loading, use `smokescreen.LoadConfigWithLogger(path, logger)` or
`cmd.NewConfiguration(args, logger)` to capture loading diagnostics.
Callers own handler flushing and cleanup. Use `ReplaceAttr` or a handler wrapper
for additional [redaction](docs/logging-redaction.md). See the
[migration notes](docs/logging-changes.md) for operator-visible changes.

### IP Filtering

To control the routing of requests to specific IP addresses or IP blocks, use the `deny-address`, `allow-address`, `deny-range`, and `allow-range` options in the config.

Overlapping explicit rules default to `allow-first`: any matching allow rule
wins over every matching deny rule. To opt into specificity-based precedence:

```yaml
most_specific_ip_rules: true
```

The equivalent CLI flag is `--most-specific-ip-rules`. Go consumers can set
`Config.MostSpecificIPRules = true`. The default is false, preserving allow-first.
An explicitly supplied CLI value overrides YAML, including
`--most-specific-ip-rules=false` to disable a YAML-enabled setting.

In `most-specific` mode, the longest matching CIDR prefix wins. At equal prefix
lengths, a port-specific rule wins over an all-port rule; deny wins remaining
ties. Address rules are single-IP networks (`/32` or `/128`). Rule order has no
effect. For example, denying `10.0.0.5` overrides allowing `10.0.0.0/24`, while
allowing `10.0.0.5:443` overrides denying `10.0.0.0/8` for that IP and port.

Ranges match all ports; addresses accept an optional port (IPv6 with a port
uses brackets, e.g. `[fd00::5]:443`). Explicit allows can bypass default IP safety
blocks, but hostname ACL checks still apply. Allow rules do not create an
exclusive allowlist: unmatched destinations follow the default safety checks.
Each DNS answer is evaluated separately; another eligible answer can still be
selected when one answer is denied. The self-connection guard takes precedence
under both policies.

Smokescreen denies connections to addresses in `Config.LocalIPs` on every port
by default, even if an address is explicitly allowed. `StartWithConfig` populates
`LocalIPs` from the host's network interfaces unless it is already set.

To disable the self-connection guard,
set `--allow-self-connections`, use the YAML setting below, or set
`Config.AllowSelfConnections = true` after calling `NewConfig()`:

```yaml
allow_self_connections: true  # defaults to false
```

With this setting enabled, connections to the proxy host on all ports, including
Smokescreen's listening port, follow normal IP and hostname ACL checks and may be
allowed.

Use the repeatable `--unsafe-ip-filter-bypassed-domain` flag, or the main
configuration setting below, to bypass IP filtering for trusted destination
hostnames:

```yaml
unsafe_ip_filter_bypassed_domains:
  - login.internal.example.com
  - "*.internal.example.com"
```

This does not bypass ACL checks and doesn't allow self-connections unless `allow_self_connections` is also true.

### Rate Limiting

Smokescreen supports rate and concurrency limiting to protect against overload:

| Option | Description |
| ------ | ----------- |
| `max-concurrent-requests` | Limits simultaneous in-flight requests. Excess requests receive `503 Service Unavailable`. |
| `max-request-rate` | Limits requests per second using a token bucket algorithm. Excess requests receive `429 Too Many Requests`. |
| `max-request-burst` | Sets token bucket capacity. Must be greater than `max-request-rate`. Defaults to 2x the rate if omitted. |
| `max-concurrent-connect-tunnels` | Limits the number of active CONNECT tunnels (long-lived connections). Unlike `max-concurrent-requests` which only tracks request processing time, this limits actual tunnel connections and prevents resource exhaustion from unbounded CONNECT tunnels. Excess requests receive `429 Too Many Requests`. |

> **Note:** `max-concurrent-requests` limits the number of requests being *processed*, while `max-concurrent-connect-tunnels` limits the number of active *tunnel connections*. For CONNECT requests, the request processing completes quickly but the tunnel connection remains open. Use both settings together for complete protection against resource exhaustion.

**Example (CLI):**
```bash
smokescreen --max-concurrent-requests=100 --max-request-rate=50 --max-concurrent-connect-tunnels=50
```

**Example (YAML):**

YAML duration values must include a unit accepted by Go (for example, `0s`,
`500ms`, or `10s`). Bare numbers are not valid duration values.

```yaml
connect_timeout: 10s  # defaults to 10s; set to 0s to disable the timeout
max_concurrent_requests: 100
max_request_rate: 50
max_request_burst: 150  # optional, defaults to 2x rate
max_concurrent_connect_tunnels: 50  # limits active CONNECT tunnel connections
```

### Hostname ACLs

A hostname ACL is a YAML file with `version: v2`. It has one entry for each service, an optional `default` for roles that have no entry, and `global` entries that apply to every role. Files with `version: v1` still load: Smokescreen converts them to an equivalent v2 policy and logs a warning to move the file to v2. See [Migrating to v2](docs/migrating-to-v2.md).

```yaml
version: v2
services:
  - name: ci
    project: ci-infra
    action: open
    proxies: [proxy.example.net]       # upstream proxies the role may CONNECT through
    allow:
      - domains: [pypi.org]
        override_global_policy: true   # wins over global.deny for pypi.org only
      - domains: [slack.com]
        mitm:
          add_headers: {X-Team: ci}
      - domains: ["sts.*.amazonaws.com"]
        cross_public_suffix: true      # see below; applies to every domain in this entry
    deny: [tracking.example.com]
default:
  project: security
  action: enforce
global:
  deny: [pypi.org, "regis*.npmjs.org"]
  allow:
    - domains: [api.partner.example]
```

Each service has an `action`, which decides requests that no entry matches:

| Policy  | Behavior                                                                                                       |
| ------- | -------------------------------------------------------------------------------------------------------------- |
| Open    | Allows all traffic for this service                                                                            |
| Report  | Allows all traffic for this service and warns if client accesses a remote host which is not in the list        |
| Enforce | Only allows traffic to remote hosts provided in the list. Will warn and deny if remote host is not in the list |

Smokescreen decides a request in this order, and the first step that matches decides:

1. A role that has no service entry uses `default`, or is denied if there is no `default`.
2. A CONNECT proxy host must match one of the service's `proxies`.
3. The service's `deny` list, then its `allow` entries.
4. The `global.deny` list, then the `global.allow` entries.
5. The service's `action`.

The order of entries in the file does not change a result. A service `allow` entry wins over `global.deny` only if it sets `override_global_policy: true`, and only for the hosts that the entry itself matches: in the example, `ci` can reach `pypi.org`, but not `registry.npmjs.org`. The ACL fails to load if a service `allow` entry overlaps `global.deny` without the field. To load an existing ACL that relies on the old behavior, where a service allow always won, start Smokescreen with `--acl-compat`, or set `acl_compat: true` in the config file. Smokescreen then logs a warning for each such entry.

Unknown keys are rejected, so a misspelled key fails to load instead of silently doing nothing. To use the ACL file as an extension point, with keys that your own tools read, start Smokescreen with `--acl-allow-unknown-fields`, or set `acl_allow_unknown_fields: true` in the config file. Smokescreen then ignores every key it does not define, as v1 did, so your tools must validate their own keys, and a misspelled Smokescreen key is ignored too.

> :warning: **The ACL is only applied to hostnames *as they appear in the request*!** If you want to allow or deny traffic based on the destination IP address *after DNS resolution*, you should be using the config options instead (see the `IP Filtering` section above).

A host can be specified with or without a wildcard, and a glob may contain at most one wildcard. The host must be in Punycode to prevent ambiguity.

- A leading `*.` matches one or more subdomain labels: `*.example.com` matches `api.example.com` and `a.b.example.com`, but not `example.com`.
- A `*` spanning a label other than the leftmost one matches exactly one label: `access-analyzer.*.amazonaws.com` matches `access-analyzer.us-west-2.amazonaws.com`, but not `access-analyzer.a.b.amazonaws.com`.
- A `*` after a literal prefix within a label matches one or more characters in that label: `api*.example.com` matches `api-east.example.com`, but not `api.example.com`, `api.a.example.com`, or `a.api-east.example.com`.

Apart from the leading `*.`, a wildcard never crosses a `.`. The labels to its right must form a registrable domain rather than a [public suffix](https://publicsuffix.org/) such as `com`, `co.uk`, or `github.io`, and the wildcard label must be lowercase ASCII.

In `allow` entries and `proxies`, these wildcards only match hosts in the same registrable domain as the labels to their right, unless the allow entry sets `cross_public_suffix: true`, according to the public suffix list. This prevents `access-analyzer.*.amazonaws.com` from matching `access-analyzer.s3.amazonaws.com`, an S3 bucket that anyone can claim. It also means that hosts that are public suffixes themselves, such as `s3.us-west-2.amazonaws.com`, or that sit directly under one, such as `access-analyzer.us-east-1.amazonaws.com`, never match a wildcard; specify such hosts explicitly. When a request is denied or reported only because of this check, the decision reason in the logs and in the response to the client says so:

```
rule has enforce policy; wildcard 'sts.*.amazonaws.com' was not applied because 'us-east-1.amazonaws.com' is on the public suffix list
```

Deny globs always match across public suffixes, so a `deny` list blocks every host that the glob's text describes. Proxy globs never do. To let an allow entry's wildcards match across public suffixes, set `cross_public_suffix: true` on the entry. The setting applies to every domain in the entry, so put domains that must not cross in a separate entry. A crossing wildcard also matches hosts that belong to other tenants, such as S3 buckets. Because a wildcard never matches an empty string or a subdomain, denying `api*.example.com` blocks neither `api.example.com` nor `v1.api-east.example.com`; deny those separately if needed.

| host                              | valid   |
| --------------------------------- | ------- |
| `example.com`                     | yes     |
| `*.example.com`                   | yes     |
| `access-analyzer.*.amazonaws.com` | yes     |
| `api*.example.com`                | yes     |
| `web*-canary.example.com`         | yes     |
| `web.qa-*.internal.example.com`   | yes     |
| `*.*.example.com`                 | no      |
| `*.api*.example.com`              | no      |
| `*example.com`                    | no      |
| `*-canary.example.com`            | no      |
| `ex*ample.com`                    | no      |
| `login.*.com`                     | no      |
| `foo*.github.io`                  | no      |
| `éxämple.com`                     | no      |
| `example.*`                       | hell no |

[Here](pkg/smokescreen/acl/v2/testdata/acl_sample.yaml) is a sample ACL.

> :warning: **A deny entry only blocks specific *hostnames*, not entire *destinations*.** For example, if `malicious.com` is in `global.deny` but the IP address that it resolves to is not, roles with an `open` action can still reach the destination by using its IP address directly. For this reason, **we recommend allow entries instead of deny entries** whenever it is possible to do so, and **blocking IP addresses via config options, not the ACL** (see the `IP Filtering` section above).

# Development and Testing

See [Development.md](Development.md)

# Releases

Smokescreen releases include standalone binaries and container images.

## Standalone Binaries

Pre-built binaries are available on the [GitHub Releases](https://github.com/stripe/smokescreen/releases) page:

- **Linux**: amd64 and arm64
- **macOS**: amd64 and arm64

## Container Images

Container images are available at `ghcr.io/stripe/smokescreen:<version>`.
Replace `<version>` with a published release tag, such as `v0.2.0`.

### Supported Platforms

- `linux/amd64` - Intel/AMD 64-bit
- `linux/arm64` - ARM 64-bit

### Running the Container

```bash
docker run --rm -p 4750:4750 ghcr.io/stripe/smokescreen:<version>
```

Smokescreen can then be used with `curl --proxy localhost:4750 http://example.com`.

To use a local ACL and a different port, mount the file and pass CLI arguments:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/acl.yaml:/config/acl.yaml:ro" \
  ghcr.io/stripe/smokescreen:<version> \
  --egress-acl-file /config/acl.yaml \
  --listen-ip 0.0.0.0 --listen-port 8080
```

The container runs as a non-root user; mounted files must be readable by it.

# Contributors

- Aditya Mukerjee
- Andreas Fuchs
- Andrew Dunham
- Andrew Metcalf
- Aniket Joshi
- Ben Ransford
- Carl Jackson
- Craig Shannon
- Evan Broder
- Marc-André Tremblay
- Ryan Koppenhaver
- Harold Simpson
