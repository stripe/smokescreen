# Redacting logs with slog

Set `Config.Log` to a standard `*slog.Logger`. For JSONHandler or TextHandler,
use `slog.HandlerOptions.ReplaceAttr` to apply your application's redaction:

```go
cfg := smokescreen.NewConfig()
cfg.Log = slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
    ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
        if attr.Key == "trace_id" {
            return slog.String(attr.Key, "[REDACTED]")
        }
        return attr
    },
}))
```

The same options work with TextHandler. For another backend, wrap its standard
`slog.Handler` and supply it through `slog.New(handler)`.

Smokescreen retains MITM header allowlisting and sanitizes structured URL fields
and typed URL errors before dispatch. Logged URLs omit userinfo, queries, and
fragments; invalid URL parse causes are replaced because they can contain
credentials. URL-bearing wrappers log sanitized causes instead of wrapper text.

Ordinary error text, decision reasons, and printf-only diagnostics are unchanged.
Additional application-specific redaction belongs in the caller handler.
`ReplaceAttr` visits slog attributes and groups, but does not recurse into maps
or structs stored in an `Any` value; replace the whole attribute when needed.
