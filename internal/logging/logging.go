// Package logging contains Smokescreen's defaults and pre-dispatch redaction.
// Integrations use log/slog directly and own their handlers' lifetimes.
package logging

import (
	"errors"
	"log"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

// OrDefault never consults or mutates the process-global default logger.
func OrDefault(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

// URL produces a log-only representation without userinfo, query, or fragment.
// Omitting the whole query avoids guessing which parameter names contain secrets.
// Malformed URLs and ambiguous bare credentials are never echoed back.
func URL(value string) string {
	prefix := ""
	if !strings.Contains(value, "://") && !strings.HasPrefix(value, "/") {
		if strings.Contains(value, "@") {
			return "[REDACTED URL]"
		}
		// Request hosts and CONNECT authorities need authority parsing, including
		// IPv6 and host:port values that Parse would otherwise treat as opaque URLs.
		prefix = "//"
	}
	parsed, err := url.Parse(prefix + value)
	if err != nil || parsed.Opaque != "" {
		return "[REDACTED URL]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return strings.TrimPrefix(parsed.String(), prefix)
}

// Error builds URL-bearing error chains from sanitized causes. Wrapper prose is
// omitted in those chains because wrappers can reformat or repeat credentials.
// Other errors are unchanged; application-specific redaction belongs to handlers.
func Error(err error) string {
	message, _ := errorText(err)
	return message
}

func errorText(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	if urlErr, ok := err.(*url.Error); ok {
		sanitized := *urlErr
		sanitized.URL = URL(urlErr.URL)
		if urlErr.Op == "parse" {
			sanitized.Err = errors.New("invalid URL")
		} else {
			sanitized.Err = errors.New(Error(urlErr.Err))
		}
		return sanitized.Error(), true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		var parts []string
		var containsURL bool
		for _, child := range wrapped.Unwrap() {
			if child == nil {
				continue
			}
			message, changed := errorText(child)
			parts = append(parts, message)
			containsURL = containsURL || changed
		}
		if containsURL {
			return strings.Join(parts, "\n"), true
		}
	case interface{ Unwrap() error }:
		if message, containsURL := errorText(wrapped.Unwrap()); containsURL {
			return message, true
		}
	}
	return err.Error(), false
}

// StdLogger bridges printf-only components to an instance's handler. Those APIs
// have no request context. Messages are forwarded unchanged to the caller handler.
func StdLogger(logger *slog.Logger) *log.Logger {
	return slog.NewLogLogger(OrDefault(logger).With(slog.String("stdlog", "1")).Handler(), slog.LevelWarn)
}
