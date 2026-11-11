# Migrating to v2

Smokescreen v2 is the Go module `github.com/stripe/smokescreen/v2`. The v1 module, `github.com/stripe/smokescreen`, does not change.

Deployments that run the `smokescreen` binary with their existing flags, config file and v1 ACL file keep working. Code that uses smokescreen as a library needs the changes below.

## Breaking changes

| Area | Change | What to do |
|---|---|---|
| Module path | Import paths gain `/v2`, for example `github.com/stripe/smokescreen/v2/pkg/smokescreen`. | Update imports, then `go get github.com/stripe/smokescreen/v2`. |
| Logging | Logrus is replaced by `log/slog`. `Config.Log` and `SmokescreenContext.Logger` are `*slog.Logger`. `cmd.NewConfiguration`, `acl.New` (v1) and conntrack's `NewInstrumentedConn` and `NewInstrumentedConnWithTimeout` take a `*slog.Logger`. `conntrack.NewTracker` no longer takes a logger. `Log2LogrusWriter` is removed. The v1 `ACL` no longer embeds a Logrus logger. | Pass `slog.New(handler)`. Use any `slog.Handler` to keep your current log backend. Log output changes are listed in [logging-changes.md](logging-changes.md). |
| ACL decisions | `Config.EgressACL` is the `acl/v2` `Decider`. `ACLDecision.MitmConfig` is an `acl/v2` `*MitmConfig`. | ACL files: nothing to do, see below. Code that builds a v1 `ACL`: call `ACL.Engine` and use the result. A custom `Decider`: change it to the `acl/v2` `DecideArgs` and `Decision` types, which have the same fields. |
| Prometheus | With `--expose-prometheus-metrics`, metrics listen on `127.0.0.1` by default. | Set `--prometheus-listen-ip 0.0.0.0` to expose metrics on other interfaces. |
| `SmokescreenContext` | The type is no longer comparable with `==`. | Compare pointers. |

No CLI flags or config file keys are removed. v2 adds `--acl-compat` (`acl_compat`) and `--acl-allow-unknown-fields` (`acl_allow_unknown_fields`) for v2 ACL files.

## ACLs

Smokescreen reads the `version` key of the ACL file:

- A `version: v1` file loads with the v1 loader and its lenient parsing. Smokescreen converts it to an equivalent v2 policy and logs a warning. It decides every request as v1 did.
- A `version: v2` file loads with the v2 format. See [Hostname ACLs](../README.md#hostname-acls).

Code that builds a v1 `ACL` itself, from YAML, in Go or from other config, converts it explicitly:

```go
a, err := acl.New(logger, loader, disabledActions)
if err != nil {
	return err
}
engine, err := a.Engine(aclv2.Options{})
if err != nil {
	return err
}
config.EgressACL = engine
```

The engine is a snapshot. Code that rebuilds the ACL at runtime calls `Engine` again after each rebuild.

`Engine` returns an error for the few v1 ACLs that v2 cannot express: an unknown policy, a rule for an empty service name, a MITM domain that is not an allowed domain, and a proxy glob with a label wildcard when `unsafe_allow_wildcards_across_public_suffixes` is set.

## Moving an ACL file to the v2 format

This step is optional. `ACL.Policy` returns the converted policy. Marshal it with a YAML library to get a v2 file to start from. The converted file sets `override_global_policy` on every service allow entry. Keep it only on the entries that need to win over `global.deny`.

| v1 | v2 |
|---|---|
| `services[].allowed_domains` | `services[].allow[].domains` |
| `services[].mitm_domains[]` | An `allow` entry with `mitm` |
| `services[].allowed_external_proxies` | `services[].proxies` |
| `default` | `default` |
| `global_deny_list` | `global.deny` |
| `global_allow_list` | `global.allow[].domains` |
| `unsafe_allow_wildcards_across_public_suffixes` | `cross_public_suffix: true` on an allow entry |
| A service's allowed domain always wins over `global_deny_list` | Set `override_global_policy: true` on that allow entry |
| Unknown keys are ignored | Unknown keys are errors, unless you use `--acl-allow-unknown-fields` |

v2 also adds a per-service `deny` list.
