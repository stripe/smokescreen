# Logging migration validation

## Reproduction

Measurements: Apple M4 Pro, darwin/arm64, Go 1.27.1, 14 logical CPUs, ten
repetitions. Baseline production code is master `9793d087`; candidate production
code is the review stack ending at `e90aeec`. A subsequent standalone stats-server
nil-logger correction does not affect these benchmark paths. The same benchmark fixtures run on
both, with only logger/tracker API setup adapted for the baseline.

```sh
go test ./pkg/smokescreen/... -run '^$' -bench . -benchmem -count=10
go run golang.org/x/perf/cmd/benchstat@latest docs/benchmarks/baseline.txt docs/benchmarks/candidate.txt
```

[Baseline samples](benchmarks/baseline.txt) and
[candidate samples](benchmarks/candidate.txt) contain the measured benchmark
records. The full suite ran first; traffic and redaction measurements were
repeated separately after removing startup diagnostics from the benchmark
harness. The files retain those repeated samples for those cases.

## Performance

Medians, baseline → candidate:

| Fixture | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| CanonicalLogging/disabled | 325.1 → 3.7 | 808 → 0 | 7 → 0 |
| CanonicalLogging/json | 3,306.5 → 511.1 | 2,833 → 160 | 54 → 1 |
| CanonicalLogging/text | 2,803.0 → 526.4 | 2,954 → 160 | 34 → 1 |
| RedactHeaders | 228.8 → 232.0 | 464 → 496 | 6 → 7 |
| ProxyTraffic/HTTP | 50,976.5 → 49,173.0 | 37,128 → 32,600 | 281 → 238 |
| ProxyTraffic/CONNECT | 42,375.0 → 42,980.5 | 5,548 → 5,536 | 62 → 62 |

The caller-handler fixture (an atomic counter delegating to stock JSONHandler)
measured 576.4 ns/op, 160 B/op, and 1 alloc/op. It has no equivalent standard slog
handler baseline before the migration.

| Parallel traffic | requests/s | p50 latency, µs/request | p99 latency, µs/request |
| --- | ---: | ---: | ---: |
| ProxyTraffic/HTTP | 19,618 → 20,336 | 673.0 → 640.7 | 1,179.5 → 1,114.6 |
| ProxyTraffic/CONNECT | 23,598 → 23,266 | 577.9 → 587.6 | 781.9 → 796.9 |

Canonical JSON time decreased 84.5%; disabled canonical logging allocates nothing.
Header redaction adds 32 bytes and one allocation to copy the two allowlisted
values in this fixture. That is the intentional cost of detaching retained
headers; its timing difference was not statistically significant (p=0.271).

HTTP throughput increased 3.7%. CONNECT throughput decreased 1.4% in this run
(p=0.002), with unchanged allocations. Inspection confirms no changes to the
connection Read/Write loops: CONNECT admission/close logging runs at tunnel
boundaries, outside the measured pooled request loop. The small measured delta
remains recorded rather than being claimed as zero overhead. These local results
do not establish production throughput or tail-latency behavior.

Traffic uses bounded pools of 128 idle connections per host on both versions.
This avoids local ephemeral-port exhaustion from the default two-idle-connection
pool under sustained parallel load. Production defaults are unchanged. Latency
sample collection is identical in both versions and included in benchmark costs.
There are no new per-event goroutines; observer work is deferred.

## Cyclomatic complexity

Measured with `github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0`, excluding test files:

| Function | Master | Candidate |
| --- | ---: | ---: |
| Config.UnmarshalYAML | 39 | 31 |
| logProxy | 8 | 6 |
| cmd.NewConfiguration | 47 | 47 |
| BuildProxy | 24 | 24 |
| dialContext | 19 | 19 |
| runServer | 13 | 13 |

Dependency preservation initially raised UnmarshalYAML to 44. Separating reset,
TLS, and MITM setup reduced the main function to 31; the helpers score 4, 6, and
8. Canonical severity selection is now a focused helper scoring 5. This is
responsibility-based decomposition, not removal of authorization or error checks.
The large CLI constructor remains outside this migration.

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
  cleanup must land before the final integration is ready to merge into master.

Production dashboards were not available for manual validation. Consumers must
validate parsers against uppercase slog levels and the standard JSON encoding
before the breaking release. Backend cleanup remains caller-owned.
