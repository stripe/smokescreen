package smokescreen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/internal/testlog"
)

func TestCallerRedactionWithReplaceAttr(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			cfg := NewConfig()
			options := &slog.HandlerOptions{
				ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
					if len(groups) == 1 && groups[0] == "proxy" && (attr.Key == LogFieldTraceID || attr.Key == LogFieldDecisionReason) {
						return slog.String(attr.Key, "[CALLER REDACTED]")
					}
					return attr
				},
			}
			var handler slog.Handler = slog.NewJSONHandler(&output, options)
			if format == "text" {
				handler = slog.NewTextHandler(&output, options)
			}
			cfg.Log = slog.New(handler).WithGroup("proxy")
			pctx := canonicalFixture(cfg)
			sctx := pctx.UserData.(*SmokescreenContext)
			sctx.Decision.Reason = "private policy reason"
			logProxy(pctx)
			require.NotContains(t, output.String(), "client-trace")
			require.NotContains(t, output.String(), "private policy reason")
			if format == "json" {
				var record map[string]any
				require.NoError(t, json.Unmarshal(output.Bytes(), &record))
				fields := record["proxy"].(map[string]any)
				require.Equal(t, "[CALLER REDACTED]", fields[LogFieldTraceID])
				require.Equal(t, "[CALLER REDACTED]", fields[LogFieldDecisionReason])
				require.Equal(t, true, fields[LogFieldAllow])
				require.Equal(t, CanonicalProxyDecision, record["msg"])
				require.Equal(t, "INFO", record["level"])
			} else {
				require.Contains(t, output.String(), `proxy.trace_id="[CALLER REDACTED]"`)
				require.Contains(t, output.String(), `proxy.decision_reason="[CALLER REDACTED]"`)
				require.Contains(t, output.String(), "proxy.allow=true")
				require.Contains(t, output.String(), "msg="+CanonicalProxyDecision)
				require.Contains(t, output.String(), "level=INFO")
			}
			require.Equal(t, "client-trace", pctx.Req.Header.Get(traceHeader))
			require.Equal(t, "private policy reason", sctx.Decision.Reason)
		})
	}
}

func TestURLDiagnosticsBeforeCallerHandler(t *testing.T) {
	_, parseErr := url.Parse("https://alice:sec/ret@proxy.example")
	require.Error(t, parseErr)
	transportErr := &url.Error{
		Op: "Get", URL: "https://alice:secret@proxy.example/?%74oken=secret",
		Err: errors.New("connection refused"),
	}
	for _, err := range []error{parseErr, transportErr, errors.Join(parseErr, transportErr), reformattedProxyError{errors.Join(parseErr, transportErr)}} {
		logger, records := testlog.New()
		cfg := NewConfig()
		cfg.Log = logger
		pctx := canonicalFixture(cfg)
		pctx.UserData.(*SmokescreenContext).dialAttrs = []slog.Attr{
			slog.String(LogFieldOutLocalAddr, "127.0.0.1:1234"),
			slog.Int64(LogFieldConnEstablishMS, 3),
		}
		pctx.Error = fmt.Errorf("proxy failure: %w", err)
		original := pctx.Error.Error()
		response := rejectResponse(pctx, pctx.Error)
		logProxy(pctx)
		for _, record := range records.AllEntries() {
			require.Equal(t, "127.0.0.1:1234", record.Data[LogFieldOutLocalAddr])
			require.Equal(t, int64(3), record.Data[LogFieldConnEstablishMS])
			if record.Level == slog.LevelError {
				require.Equal(t, int64(response.StatusCode), record.Data["status_code"])
			}
			for _, value := range []any{record.Message, record.Data[LogFieldError]} {
				if value != nil {
					require.NotContains(t, value, "alice")
					require.NotContains(t, value, "secret")
					require.NotContains(t, value, "sec/ret")
				}
			}
		}
		require.Equal(t, original, pctx.Error.Error())
		require.Contains(t, response.Header.Get(errorHeader), original)
	}
}

type reformattedProxyError struct{ error }

func (e reformattedProxyError) Error() string { return "reformatted: alice secret sec/ret" }
func (e reformattedProxyError) Unwrap() error { return e.error }

func TestCanonicalDiagnosticsPreserveText(t *testing.T) {
	logger, records := testlog.New()
	cfg := NewConfig()
	cfg.Log = logger
	pctx := canonicalFixture(cfg)
	message := "retry? See https://example.com/help#timeout or contact operator@example.com"
	pctx.Error = errors.New(message)
	pctx.UserData.(*SmokescreenContext).Decision.Reason = message
	logProxy(pctx)
	record := records.LastEntry()
	require.NotNil(t, record)
	require.Equal(t, message, record.Data[LogFieldError])
	require.Equal(t, message, record.Data[LogFieldDecisionReason])
}
