# Logging migration validation

## Reproduction

Benchmark code and the saved measurements below are grouped in PR 4. PR 1
contains correctness tests only. Candidate measurements were refreshed after the
PR 2 review fixes.

Measurements: Apple M4 Pro, darwin/arm64, Go 1.27.1, 14 logical CPUs, ten
repetitions. Baseline production code is master `9793d087`; candidate production
code is the review stack ending at `1c67b08`, including the PR 2 review fixes
through `5e4594c`. Baseline samples are retained from the earlier run on the same machine;
these measurements were not interleaved. The same benchmark fixtures run on both,
with only logger/tracker API setup adapted for the baseline.

```sh
go test ./pkg/smokescreen/... -run '^$' -bench . -benchmem -count=10
go run golang.org/x/perf/cmd/benchstat@latest docs/benchmarks/baseline.txt docs/benchmarks/candidate.txt
```

[Baseline samples](benchmarks/baseline.txt) and
[candidate samples](benchmarks/candidate.txt) contain the measured benchmark
records. Each fixture has ten samples. Baseline traffic and header-redaction
samples come from the earlier rerun that removed startup diagnostics from the
harness. The refreshed candidate ran the full benchmark command above.

## Performance

Medians, baseline → candidate:

| Fixture | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| CanonicalLogging/disabled | 325.1 → 3.5 | 808 → 0 | 7 → 0 |
| CanonicalLogging/json | 3,306.5 → 473.2 | 2,833 → 160 | 54 → 1 |
| CanonicalLogging/text | 2,803.0 → 490.9 | 2,954 → 160 | 34 → 1 |
| RedactHeaders | 228.8 → 220.4 | 464 → 496 | 6 → 7 |
| ProxyTraffic/HTTP | 50,976.5 → 49,368.5 | 37,128 → 33,167 | 281 → 240 |
| ProxyTraffic/CONNECT | 42,375.0 → 43,053.5 | 5,548 → 5,537 | 62 → 62 |

The caller-handler fixture (an atomic counter delegating to stock JSONHandler)
measured 514.6 ns/op, 160 B/op, and 1 alloc/op. It has no equivalent standard slog
handler baseline before the migration.

| Parallel traffic | requests/s | p50 latency, µs/request | p99 latency, µs/request |
| --- | ---: | ---: | ---: |
| ProxyTraffic/HTTP | 19,618 → 20,256 | 673.0 → 647.2 | 1,179.5 → 1,124.0 |
| ProxyTraffic/CONNECT | 23,598 → 23,227 | 577.9 → 588.7 | 781.9 → 806.3 |

Canonical JSON time decreased 85.7%; disabled canonical logging allocates nothing.
Header redaction adds 32 bytes and one allocation to copy the two allowlisted
values in this fixture. That is the intentional cost of detaching retained
headers.

HTTP throughput increased 3.3%. CONNECT throughput decreased 1.6% (p=0.002),
with unchanged median allocations; p99 latency increased 3.1% (p=0.011). Inspection
confirms unchanged connection Read/Write loops. Field snapshots occur at dial,
error, and close boundaries, outside the pooled CONNECT request loop. The measured
slowdown remains recorded; these non-interleaved local samples do not establish
causality or production throughput and tail-latency behavior. HTTP measures 240
allocations/request, compared with 281 in the baseline.

Traffic uses bounded pools of 128 idle connections per host on both versions.
This avoids local ephemeral-port exhaustion from the default two-idle-connection
pool under sustained parallel load. Production defaults are unchanged. Latency
sample collection is identical in both versions and included in benchmark costs.
There are no new per-event goroutines; observer work is deferred.

## Cyclomatic complexity

Measured with `github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0`, excluding test files:

| Function | Master | Candidate |
| --- | ---: | ---: |
| Config.UnmarshalYAML | 39 | 19 |
| logProxy | 8 | 6 |
| cmd.NewConfiguration | 47 | 47 |
| BuildProxy | 24 | 24 |
| dialContext | 19 | 19 |
| runServer | 13 | 13 |
| logging.URL | — | 6 |
| logging.errorText | — | 11 |
| SmokescreenContext.diagnosticLogger | — | 3 |

YAML applies only supplied keys; it no longer resets the config and restores an
allowlist. Rule, rate-limit, and TLS helpers score 6; MITM setup scores 8.
Canonical severity selection scores 5. The CLI constructor is unchanged.

## Correctness checks

- Unit tests, race tests, vet, and the hermetic integration suite pass on Go 1.27.1.
  Unit tests also pass on the minimum supported Go version, 1.25.7.
- Every implementation branch in the review stack passes `go test ./...`.
- Stock JSON, stock text, caller, failing, and disabled handlers cover HTTP,
  CONNECT, MITM, and denial with the same proxy outcomes.
- Tests cover canonical fields/levels/units, copied headers, URL redaction before
  handler dispatch, caller groups, backend isolation, canceled logging contexts,
  independent DNS timeouts, unchanged custom/default dialing, repeated close,
  fatal exit(1), and graceful/immediate shutdown in subprocesses.
- Existing tests cover response-hook failures, malformed requests, role failures,
  IP/DNS rejection, upstream proxies, half-close, timeouts, and tunnel limits.
- Migration examples and custom ACL/tracker implementations compile. The
  recording handler passes `testing/slogtest`.
- Source/import and compiled dependency checks find no Logrus usage. The existing
  module requirement, sums, and vendor files remain unchanged intentionally.
- The existing CI vendor-regeneration job is expected to report differences after
  the API migration. It is not bypassed: the separately deferred dependency/vendor
  cleanup remains deferred and must be resolved before the final v1 release.

Production dashboards were not available for manual validation. Consumers must
validate parsers against uppercase slog levels and the standard JSON encoding
before the breaking release. Backend cleanup remains caller-owned.
