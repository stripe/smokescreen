# Logging migration

Smokescreen uses standard `log/slog`. Its default is an instance-local
`slog.New(slog.NewJSONHandler(os.Stderr, nil))`, at INFO level. Nil loggers use
that default; neither `slog.Default()` nor the standard global logger is changed.
The module path and minimum Go version (1.25) are unchanged.

## Supplying a backend

```go
cfg := smokescreen.NewConfig() // JSON to stderr
cfg.Log = slog.New(slog.NewTextHandler(w, nil)) // text to your writer
cfg.Log = slog.New(callerHandler) // any standard slog.Handler
```

Callers own sinks, level filtering, buffering, flushing, closing, and exporter
shutdown. Smokescreen does not reconfigure or close a supplied handler. Handlers
are synchronous and may add request latency; integrations own queueing and
backpressure. Handlers must support concurrent calls as required by slog.

Set `cfg.Log` before `cfg.LoadFile(path)`, or pass your logger to
`cmd.NewConfiguration(args, logger)`, to capture configuration and ACL-loading
diagnostics. YAML loading preserves injected dependencies unless the file
explicitly configures their replacement.

## API changes

- `Config.Log` and `SmokescreenContext.Logger` are `*slog.Logger`.
- CLI and ACL constructors accept `*slog.Logger`. ACL no longer embeds a logger.
- Tracker connection constructors accept `context.Context` first and
  `*slog.Logger` in place of an entry; `NewTracker` no longer
  takes its unused logger argument. Update custom tracker implementations too.
- Replace `WithField("role", role)` with `With(slog.String("role", role))`.
  Replace `WithFields` with individual typed attributes. Use `slog.Int64`,
  `slog.Uint64`, `slog.Bool`, and `slog.Time` to preserve types.
- Configure levels through `slog.HandlerOptions`, optionally using a caller-owned
  `slog.LevelVar`. There is no backend registry or permanent logging adapter.

HTTP server and goproxy printf diagnostics use instance-specific
`slog.NewLogLogger` bridges at WARN, retaining `stdlog="1"`. These APIs cannot
carry request context. The bridge forwards diagnostic text unchanged.

## Request context and correlation

Use `InfoContext`, `WarnContext`, `ErrorContext`, or `LogAttrs` with the available
request context. Smokescreen passes that context through request checks,
resolution/dial diagnostics, rejection, and tracked connection closure. Close
logs may receive an already canceled context; it never controls connection
lifetime. DNS timeouts, built-in/custom dialing, and shutdown ownership are
unchanged.

MITM inner requests have distinct `id` values and a `parent_id` referring to their
CONNECT request. An inner request without its own client trace header retains the
CONNECT's client `trace_id`. These client-supplied values are untrusted; a caller
handler can read trusted trace metadata independently from `context.Context`.
Request IDs and destinations are not added to built-in metric labels.

Bind stable integration fields using `With` and optionally `WithGroup`. Reserve
Smokescreen's application field names within its group to avoid caller-created
collisions. Changing decision/status fields are emitted from current state.

## Canonical records and formatting

`CANONICAL-PROXY-DECISION` and `CANONICAL-PROXY-CN-CLOSE` retain their application
fields, levels, units, omission rules, and emission boundaries. CONNECT admission
is recorded before forwarding; it does not establish successful dialing. HTTP
connections remain pooled. Canonical connection-close records precede the
existing wait-group completion and underlying socket close.

JSON uses stock slog formatting. For example, an allowed decision changes from:

```json
{"level":"info","msg":"CANONICAL-PROXY-DECISION","time":"2026-09-22T10:00:00Z","allow":true}
```

to:

```json
{"time":"2026-09-22T10:00:00Z","level":"INFO","msg":"CANONICAL-PROXY-DECISION","allow":true}
```

WARN replaces `warning`; fatal paths emit ERROR before the existing exit(1).
Timestamp formatting, escaping, and key order follow the standard handler.
Update parsers that depended on legacy formatting, or supply your own handler.
DNS/connect timings remain integer milliseconds and connection duration remains
floating-point seconds. Byte counters are detached integer snapshots.

Smokescreen redacts before dispatch to any backend. MITM detailed logging still
requires opt-in and retains the header allowlist and `[REDACTED]` markers; retained
header slices are copied. Logged URLs omit userinfo, the whole query, and the
fragment. Typed URL errors are sanitized while retaining wrapper text. Ordinary
diagnostics are unchanged. These URL security corrections do not change proxy
decisions or client responses.

For additional application-specific redaction, use `slog.HandlerOptions.ReplaceAttr`
with the stock JSON/text handlers or wrap a standard `slog.Handler`. See
[redaction examples and baseline behavior](logging-redaction.md); there is no
separate redactor API. Smokescreen's baseline runs before these caller hooks.

Structured observers are deferred. Existing built-in metrics remain unchanged.
The unused logging dependency and vendor entries are deliberately retained for a
deferred cleanup; this migration does not run module tidy or vendoring.
