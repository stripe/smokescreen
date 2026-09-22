# Smokescreen v1.0.0 — four-PR logging migration

Target release: **v1.0.0**. Develop and merge this series on
`release-v1.0.0`, created from master `9793d087`. Keep master on the existing
release line throughout development. The Go module remains
`github.com/stripe/smokescreen`: v1 does not need a `/v1` suffix or import changes.

The previous nine-part breakdown becomes four implementation PRs. Keep the
existing commits inside each PR so reviewers can inspect the smaller steps.
The observer API remains out of scope. Dependency/vendor cleanup remains deferred
for now; no module tidy or vendor regeneration is included in PR 2.

| New PR | Combines previous PRs | Purpose |
| --- | --- | --- |
| 1 | 1 (correctness tests) + 2 | Existing behavior checks and the recording handler |
| 2 | 3 + 4 + 5 | Complete slog API migration, defaults, redaction, and configuration |
| 3 | 6 + 7 | Request context and MITM correlation |
| 4 | 8 + 9 + performance tests from 1 | Backend/lifecycle validation, benchmarks and results, examples, docs, and release readiness |

## PR 1 — Protect existing behavior

**Why:** Operational consumers rely on canonical fields and timing, while proxy
correctness depends on existing timeout and cleanup behavior. Capture those
contracts before changing logging. The recording handler belongs here because
it supplies the test infrastructure used by the migration.

Branch: `shubh/v1-slog-01-baseline` · Initial base: `release-v1.0.0`

[Merged PR #311](https://github.com/stripe/smokescreen/pull/311)

- Characterize canonical messages, levels, fields, types, units, omission rules,
  DNS timeout behavior, fatal exits, repeated close, and cleanup ordering.
- Add the concurrency-safe test-only slog recording handler, including retained
  record cloning, attributes/groups, context capture, and `testing/slogtest`.

Performance benchmarks and their saved measurements are reviewed together in
PR 4; PR 1 contains correctness tests only.

## PR 2 — Migrate logging as one buildable change

**Why:** Public Logrus types couple integrations to one backend. The signatures,
call sites, configuration loading, bridges, and redaction must change together
so a caller's logger is used from startup onward and structured URL credentials
are sanitized before dispatch. Combining the three original PRs avoids introducing unused
production utilities and a temporary compatibility layer.

Branch: `shubh/v1-slog-02-migration` · Base: `release-v1.0.0` (includes merged PR 1)

[PR #312](https://github.com/stripe/smokescreen/pull/312)

- Migrate public logging types, implementation, and existing tests to `*slog.Logger`.
- Use instance-local stock JSON defaults and consistent nil-logger resolution.
- Install supplied dependencies before configuration diagnostics and preserve
  them through YAML loading; apply only supplied keys without resetting the config.
- Replace ACL logger embedding with a private field, remove the unused
  `NewTracker` logger parameter, and replace the legacy writer with instance
  standard-log bridges.
- Preserve canonical boundaries, severity selection, field semantics, and
  redaction before dispatch; snapshot counters as integers and copy headers.
- Include compilable backend/custom ACL/tracker examples and the standalone
  stats-server nil-logger correction and regression, moved forward from PR 4.
- Keep Logrus in `go.mod`, `go.sum`, and `vendor/` for now. Dependency cleanup
  and vendor regeneration remain deferred. The existing vendor check remains
  enabled and is expected to report the pending cleanup.

Review PR 2 commit by commit. Caller redaction uses `ReplaceAttr` or a standard
`slog.Handler`; built-in protection targets URL fields, typed URL errors, and
MITM headers. Ordinary diagnostics retain their text. Review fixes add typed dial
attributes, restored diagnostic fields, error-tree redaction, and timestamp coverage;
invalid YAML socket modes now return errors.

## PR 3 — Carry request context and correlation

**Why:** Caller handlers need request context for trusted tracing metadata, and
MITM requests need an explicit link to their CONNECT parent. These are one
coherent correlation change, distinct from replacing the backend APIs.

Branch: `shubh/v1-slog-03-correlation` · Initial base: `shubh/v1-slog-02-migration`

[Review diff](https://github.com/stripe/smokescreen/compare/shubh/v1-slog-02-migration...shubh/v1-slog-03-correlation)

- Carry available context through checks, resolution/dial diagnostics,
  rejection, and connection-close logging.
- Add context to tracked-connection construction for diagnostics, retaining it
  after cancellation without letting it control connection lifetime.
- Give MITM inner requests distinct IDs and a CONNECT `parent_id`, preserving
  client trace fallback separately from trusted tracing metadata.
- Protect DNS/default/custom dial semantics, cleanup order, and stable
  attributes without duplicate changing fields. No observer callbacks.

## PR 4 — Verify integrations and prepare consumers for v1

**Why:** Helper tests cannot establish that backend choice leaves proxy behavior
unchanged. End-to-end validation and compilable migration examples provide that
evidence; documentation explains the breaking signatures and formatting changes
that consumers must adopt before the first stable release.

Branch: `shubh/v1-slog-04-release-readiness` · Initial base: `shubh/v1-slog-03-correlation`

[Review diff](https://github.com/stripe/smokescreen/compare/shubh/v1-slog-03-correlation...shubh/v1-slog-04-release-readiness)

- Cover HTTP, CONNECT, MITM, and denial using stock JSON/text and caller,
  disabled, and erroring handlers; verify backend isolation and redaction.
- Exercise graceful/immediate shutdown and validate the integration behavior
  around the APIs and compilable examples introduced in PR 2.
- Add logging/redaction and parallel HTTP/CONNECT benchmarks together with
  baseline/candidate samples and the performance comparison report.
- Document standard formatting, context/correlation, caller-owned cleanup,
  migration steps, benchmark comparisons, and cyclomatic-complexity results.
  Keep unrelated control-flow refactors out of this migration.
- Enable security checks on pushes to `release-v1.0.0`. Unit/race/integration
  workflows already cover all push and PR branches.
- Record release validation, including downstream consumer and dashboard
  checks still to be completed. Dependency cleanup remains separately deferred
  and must be resolved before the final release.

## Review and merge flow

PR 1 is merged: [#311](https://github.com/stripe/smokescreen/pull/311).
PR 2 is open against the release branch: [#312](https://github.com/stripe/smokescreen/pull/312).
The remaining branches are restacked on the merged PR 1 and updated PR 2;
PRs 3–4 will be opened separately. The previous nine branches remain available
as historical references.

Review the series using the initial bases above. The first PR targets
`release-v1.0.0`; later PRs target their predecessors to show only their own
changes. Before merging each subsequent PR, retarget it to `release-v1.0.0` once
its predecessor has landed. If merges are squashed or rewritten, rebase the
remaining stack so previously reviewed changes do not reappear. All four merge
into the release branch, never master during development.

Configure branch protection on `release-v1.0.0` to require review and the normal
checks before merging; branch creation alone does not enable protection. Keep
master protected as well. Protection is a repository setting and has not been
configured by this change. Carry required fixes from master into the release
line as needed, rerunning relevant checks; do not merge unfinished v1 changes
back into master.

## Release and cut over v1 together

Keep the initial v1 scope focused on the logging migration and its supporting
compatibility, security, and validation work. Complete the four implementation
PRs on the release branch, then bring the finished v1 changes onto master
together at a coordinated release cutover.

1. Finish the four PRs on `release-v1.0.0` and resolve the deferred dependency
   cleanup before release. Require unit, race, vet, integration, vendor, and security checks to
   pass. Recheck performance and downstream migration expectations.
2. Publish an explicitly approved prerelease such as `v1.0.0-alpha.1`, followed
   by `v1.0.0-rc.1`, from reviewed commits on that branch. Consumers opt in using
   `go get github.com/stripe/smokescreen@v1.0.0-rc.1`; imports stay unchanged.
   Publishing tags/releases is a later action, not part of preparing this stack.
3. Validate representative embedded consumers, dashboards, redaction, and
   graceful/immediate shutdown against the release candidate. Scheduled GitHub
   Actions run on the default branch, so use release-branch pushes or explicit
   workflow dispatch for fresh security checks on the candidate.
4. Once validated and approved, promote the completed v1 changes to master
   through the normal reviewed merge process, tag the tested release commit
   `v1.0.0`, and publish release notes linking the migration guide. Coordinate
   these as the release cutover; no partial API migration lands on master.

These are four implementation PRs, followed by the coordinated release/promotion
step. No branch rename, reset, or force-push of master is needed. Git technically
allows the release tag to point to a tested commit on `release-v1.0.0`; promoting
the completed changes together is the chosen development and cutover plan.

The branch isolates development, not dependency selection: publishing stable
`v1.0.0` makes it eligible for Go's `@latest` on the same module path even while
master stays on v0. Consumers pinned to `v0.1.0` keep that version; consumers
using `@latest` can receive the breaking upgrade. State that explicitly in the
release notes. Prereleases allow opt-in testing while the existing stable v0
release remains available.
