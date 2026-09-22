// Package logging contains Smokescreen's defaults and pre-dispatch redaction.
// Integrations use log/slog directly and own their handlers' lifetimes.
package logging

import (
	"io"
	"log"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// OrDefault never consults or mutates the process-global default logger.
func OrDefault(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

var userinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://|//)[^/?#\r\n]*@`)

// Invalid proxy configuration can omit or corrupt the scheme. Such values also
// appear verbatim in url.Parse errors, so redact credentials there as well.
var bareUserinfo = regexp.MustCompile(`[^\s"'<>/?#:@]+:[^/?#\r\n]*@`)
var querySecret = regexp.MustCompile(`(?i)([?&](?:access_token|token|api_key|apikey|key|password|passwd|secret|authorization|signature|x-amz-signature|x-amz-credential|x-amz-security-token)=)[^&#\s"']*`)

// Sanitize removes URL credentials from diagnostics before any handler sees them.
func Sanitize(value string) string {
	if strings.Contains(value, "@") {
		value = userinfo.ReplaceAllString(value, "${1}[REDACTED]@")
		value = bareUserinfo.ReplaceAllString(value, "[REDACTED]@")
	}
	if strings.ContainsAny(value, "?&") {
		value = querySecret.ReplaceAllString(value, "${1}[REDACTED]")
	}
	return value
}

// URL also fails closed for malformed credential-bearing URL fields.
func URL(value string) string {
	if _, err := url.Parse(value); err != nil && strings.Contains(value, "@") {
		return "[REDACTED URL]"
	}
	if !strings.Contains(value, "://") && !strings.HasPrefix(value, "//") && strings.Contains(value, "@") {
		return "[REDACTED URL]"
	}
	return Sanitize(value)
}

// StdLogger bridges printf-only components to an instance's handler. Those APIs
// have no request context. Redaction happens before the slog bridge dispatches.
func StdLogger(logger *slog.Logger) *log.Logger {
	bridge := slog.NewLogLogger(OrDefault(logger).With(slog.String("stdlog", "1")).Handler(), slog.LevelWarn)
	bridge.SetOutput(redactingWriter{bridge.Writer()})
	return bridge
}

type redactingWriter struct{ output io.Writer }

func (w redactingWriter) Write(p []byte) (int, error) {
	_, err := w.output.Write([]byte(Sanitize(string(p))))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
