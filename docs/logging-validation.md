# Logging migration validation

## Reproduction

Benchmark code and the saved measurements below are grouped in PR 4. PR 1
contains correctness tests only. The saved candidate measurements below precede
the diagnostic-preservation follow-up in PR 2.

Measurements: Apple M4 Pro, darwin/arm64, Go 1.27.1, 14 logical CPUs, ten
repetitions. Baseline production code is master `9793d087`; candidate production
code is the review stack ending at `166f543`, including the redaction change
`cbdc589`. Baseline samples are retained from the earlier run on the same machine;
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
| CanonicalLogging/disabled | 325.1 → 3.6 | 808 → 0 | 7 → 0 |
| CanonicalLogging/json | 3,306.5 → 493.8 | 2,833 → 160 | 54 → 1 |
| CanonicalLogging/text | 2,803.0 → 515.9 | 2,954 → 160 | 34 → 1 |
| RedactHeaders | 228.8 → 235.6 | 464 → 496 | 6 → 7 |
| ProxyTraffic/HTTP | 50,976.5 → 48,711.5 | 37,128 → 32,364 | 281 → 239 |
| ProxyTraffic/CONNECT | 42,375.0 → 42,440.0 | 5,548 → 5,534 | 62 → 62 |

The caller-handler fixture (an atomic counter delegating to stock JSONHandler)
measured 549.0 ns/op, 160 B/op, and 1 alloc/op. It has no equivalent standard slog
handler baseline before the migration.

| Parallel traffic | requests/s | p50 latency, µs/request | p99 latency, µs/request |
| --- | ---: | ---: | ---: |
| ProxyTraffic/HTTP | 19,618 → 20,529 | 673.0 → 632.4 | 1,179.5 → 1,097.2 |
| ProxyTraffic/CONNECT | 23,598 → 23,563 | 577.9 → 581.3 | 781.9 → 779.5 |

Canonical JSON time decreased 85.1%; disabled canonical logging allocates nothing.
Header redaction adds 32 bytes and one allocation to copy the two allowlisted
values in this fixture. That is the intentional cost of detaching retained
headers; its timing difference was not statistically significant (p=0.148).

HTTP throughput increased 4.7%. CONNECT throughput changed by -0.2%, which
was not statistically significant (p=0.542), with unchanged allocations. The
refreshed HTTP candidate measures 239 allocations/request, one more than the
earlier candidate's 238 following the URL-redaction changes, and 42 fewer than
baseline. No connection Read/Write loops changed: CONNECT admission/close logging
runs at tunnel boundaries, outside the measured pooled request loop. These local
results do not establish production throughput or tail-latency behavior.

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
| logging.URL | — | 6 |
| logging.Error | — | 4 |

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
  cleanup remains deferred and must be resolved before the final v1 release.

Production dashboards were not available for manual validation. Consumers must
validate parsers against uppercase slog levels and the standard JSON encoding
before the breaking release. Backend cleanup remains caller-owned.
