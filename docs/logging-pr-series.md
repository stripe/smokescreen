# Smokescreen v1.0.0 — PR plan

Develop on `release-v1.0.0`, created from master `9793d087`. The config changes
are now a separate prerequisite, making **five PRs**. Existing branch names stay
unchanged. Review each PR's commits separately; observers remain deferred.

| Order | PR / branch | What changes | Why it is needed |
| --- | --- | --- | --- |
| 1 | [#311](https://github.com/stripe/smokescreen/pull/311), merged | Canonical/lifecycle characterization and the test recording handler | Protect existing behavior before replacing logging |
| 2 | [#314](https://github.com/stripe/smokescreen/pull/314), `shubh/v1-config-loading` | Apply only supplied YAML settings; preserve injected dependencies; install CLI logger before loading | Review configuration and security semantics independently |
| 3 | [#312](https://github.com/stripe/smokescreen/pull/312), `shubh/v1-slog-02-migration` | Standard slog APIs/defaults/bridges, typed fields, redaction, and backend examples | Let callers choose handlers while retaining canonical semantics |
| 4 | `shubh/v1-slog-03-correlation` | Request contexts and distinct MITM IDs linked to CONNECT | Supply tracing context without changing request execution |
| 5 | `shubh/v1-slog-04-release-readiness` | Backend/shutdown tests, benchmarks with results, migration and release docs | Demonstrate equivalent proxy behavior and prepare consumers |

## Review boundaries

The config PR has two commits: YAML semantics/tests/docs, then CLI logger
initialization. Omitted security flags retain caller values; either allow/deny
key replaces its combined list, including caller entries. Explicit empty lists
clear rules, and the public setters still append. Burst alone leaves limiting
disabled. Invalid socket modes return errors. See [configuration notes](config-loading.md).

The logging PR retains separate commits for API migration, redaction, timestamp
coverage, typed attributes, response diagnostics, and documentation. Its only
loader change is resolving a nil logger through the slog default. JSON retains
nanoseconds; text uses milliseconds. See [logging changes](logging-changes.md).

The correlation PR has two commits: context propagation and MITM parent linkage.
DNS timeouts, dialing, connection lifetime, and cleanup remain unchanged. The
readiness PR groups performance benchmarks with their saved results; the baseline
PR contains correctness tests only.

## Merge order

Review bases: config → `release-v1.0.0`; logging → config; correlation → logging;
readiness → correlation. The correlation and readiness PRs have not been opened.
After each predecessor merges, retarget the next PR to `release-v1.0.0` and
restack if history was squashed. No partial migration lands on master.

Logrus module/vendor cleanup remains deferred. The vendor check passes on the
config PR and fails after the slog migration; this remains an unresolved merge
blocker, not approval to merge red checks. Do not disable the check. Keep normal
review and branch protection requirements; protection is a repository setting
and has not been configured by this work.

## Release and cutover

1. Finish the five PRs on the release branch, resolve dependency/vendor cleanup,
   and bring in needed master fixes. Require unit, race, vet, integration, vendor,
   and security checks to pass.
2. Publish approved opt-in prereleases such as `v1.0.0-alpha.1` and `v1.0.0-rc.1`
   from reviewed release-branch commits. Validate embedded consumers, dashboard
   parsers, redaction, and graceful/immediate shutdown against the candidate.
3. Promote the completed v1 changes to master together through a reviewed merge,
   then tag the tested release commit `v1.0.0` and publish migration notes.
   No tags or releases are published as part of preparing these PRs.

The module remains `github.com/stripe/smokescreen`; v1 needs no import suffix.
Stable `v1.0.0` becomes eligible for Go's `@latest` regardless of which branch
holds the tag. Prereleases provide opt-in testing while stable v0 remains available.
No branch rename, reset, or force-push of master is needed.
