# Smokescreen v1.0.0 — four-PR plan

Develop on `release-v1.0.0`; keep master on its existing API until the coordinated
v1.0.0 cutover. The general YAML redesign in #314 is withdrawn. Observers and
Logrus dependency/vendor cleanup remain deferred.

| Order | PR / branch | What changes | Why it is needed |
| --- | --- | --- | --- |
| 1 | [#311](https://github.com/stripe/smokescreen/pull/311), merged | Canonical/lifecycle characterization and the test recording handler | Protect existing behavior before replacing logging |
| 2 | [#312](https://github.com/stripe/smokescreen/pull/312), `shubh/v1-slog-02-migration` | Standard slog APIs, instance defaults/bridges, typed fields, redaction, and examples | Let callers choose handlers while retaining canonical semantics |
| 3 | `shubh/v1-slog-03-correlation` | Request contexts and distinct MITM IDs linked to CONNECT | Supply tracing context without changing request execution |
| 4 | `shubh/v1-slog-04-release-readiness` | Backend/shutdown tests, benchmarks with results, migration and release docs | Demonstrate equivalent proxy behavior and prepare consumers |

## Review #312 commit by commit

1. Stock slog defaults/bridges and URL-redaction helpers with tests.
2. Public APIs, call sites, canonical/diagnostic fields, and existing test migration.
3. `LoadConfigWithLogger(path, logger)` plus CLI wiring and regression tests.
   This loads a fresh configuration and captures initialization diagnostics.
   YAML settings, defaults, and fatal exits remain unchanged; there is no
   `LoadFile` or configuration-overlay API.
4. Backend examples and concise logging migration notes.

The correlation PR has two commits: context propagation and MITM parent linkage.
DNS timeouts, dialing, connection lifetime, and cleanup remain unchanged.
Performance benchmarks and their saved measurements belong together in PR 4;
PR 1 contains correctness tests only.

## Merge and release

#312 targets `release-v1.0.0`. The later branches target their predecessors;
retarget each to the release branch after its predecessor lands, restacking after
squash merges. Correlation/readiness PRs have not been opened.

Vendor verification remains unresolved after the slog migration because Logrus
cleanup is deferred. The check stays enabled; there is no assumed approval to
merge red CI. Keep normal review and branch-protection requirements.

1. Complete the four PRs on the release branch, resolve dependency/vendor cleanup,
   and bring in needed master fixes. Require unit, race, vet, integration, vendor,
   and security checks to pass.
2. Publish approved opt-in prereleases such as `v1.0.0-alpha.1` and `v1.0.0-rc.1`.
   Validate embedded consumers, dashboard parsers, redaction, and shutdown.
3. Promote the completed changes to master through a reviewed merge, tag the
   tested release commit `v1.0.0`, and publish migration notes. No partial API
   migration lands on master; no tags/releases are published in this work.

The module remains `github.com/stripe/smokescreen`; v1 needs no import suffix.
Stable `v1.0.0` becomes eligible for Go's `@latest` regardless of branch. Use
prereleases for opt-in testing while stable v0 remains available.
