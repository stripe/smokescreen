# Logging migration notes

- Stock JSONHandler preserves RFC3339Nano timestamps, including `time`,
  `start_time`, `end_time`, and `last_activity`. Stock TextHandler uses milliseconds;
  callers needing different formatting can use `ReplaceAttr` or another handler.
- Levels use slog's uppercase spelling. Startup/CRL diagnostics previously printed
  to stdout now use the configured logger (stderr by default); their existing
  INFO level and `warn:`/`error:` message prefixes are retained.
- Smokescreen no longer redirects the process-global `log` logger. Its HTTP servers
  and goproxy have explicit bridges; other dependencies keep their own logging.
- MITM detailed/debug URL logs omit credentials, queries, and fragments.
  URL-bearing error wrappers log sanitized causes rather than arbitrary wrapper text.
- Fatal paths still emit ERROR then exit(1), without running deferred flushes.
  Callers own backend cleanup; use synchronous output when fatal records must persist.
