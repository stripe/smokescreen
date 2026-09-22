# Logging migration review stack

This breaking change is developed off master `9793d087`. The assembled result is
on `shubh/smokescreen-slog-migration`. Each smaller branch below adds one reviewable
change and passes `go test ./...` independently. PRs are stacked against the
preceding branch; the first uses master as its base.

| Order | Branch | Change |
| --- | --- | --- |
| 1 | `shubh/slog-01-baseline` | Canonical semantics, execution boundaries, benchmarks |
| 2 | `shubh/slog-02-recording-handler` | Concurrent slog test handler and slogtest conformance |
| 3 | `shubh/slog-03-redaction` | Instance defaults and pre-dispatch URL redaction utilities |
| 4 | `shubh/slog-04-config-loading` | Preserve injected dependencies; decompose YAML initialization |
| 5 | `shubh/slog-05-api-migration` | Atomic public/API/implementation migration to slog |
| 6 | `shubh/slog-06-request-context` | Logging contexts without changing execution cancellation |
| 7 | `shubh/slog-07-mitm-correlation` | Distinct inner request IDs, CONNECT parent correlation |
| 8 | `shubh/slog-08-validation` | Backend matrix, shutdown checks, compilable examples |
| 9 | `shubh/slog-09-documentation` | Migration guide, performance/complexity results, final nil-logger regression |

Keep the review stack in draft while the breaking release is being prepared.
The public API switch stays atomic so intermediate branches build without a
compatibility adapter. The independent observer API is excluded from this series.

After review, complete the separately deferred dependency cleanup and vendor
regeneration. CI's existing vendor check is expected to report a diff until that
happens; the workflow is not disabled. Then open a final integration PR from the
completed series to master and merge normally. Do not replace or rename master.

Select and document the release version before that merge. A major v2 release
requires `/v2` in the module and import paths; the name of this plan does not make
that release decision. No module rename or release publication occurs here.
