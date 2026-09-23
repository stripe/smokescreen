package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stripe/smokescreen/internal/testlog"
)

func TestJSONTimestampPrecision(t *testing.T) {
	stamp := time.Date(2026, time.September, 22, 12, 34, 56, 123456789, time.UTC)
	record := slog.NewRecord(stamp, slog.LevelInfo, "timestamp precision", 0)
	for _, key := range []string{"start_time", "end_time", "last_activity"} {
		record.AddAttrs(slog.Time(key, stamp))
	}
	var output bytes.Buffer
	if err := slog.NewJSONHandler(&output, nil).Handle(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"time", "start_time", "end_time", "last_activity"} {
		if got := fields[key]; got != stamp.Format(time.RFC3339Nano) {
			t.Errorf("%s lost timestamp precision: %v", key, got)
		}
	}
}

func TestURL(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://alice:secret@proxy.example:443/path", "https://proxy.example:443/path"},
		{"//alice:secret@proxy.example/path", "//proxy.example/path"},
		{"https://example.com/?%74oken=secret&client_secret=other#secret", "https://example.com/"},
		{"https://example.com/?unknown_key=secret", "https://example.com/"},
		{"/path?token=secret#secret", "/path"},
		{"/path@name", "/path@name"},
		{"proxy.example:443", "proxy.example:443"},
		{"[::1]:443", "[::1]:443"},
		{"https://alice:sec/ret@proxy.example", "[REDACTED URL]"},
		{"https://alice:secret with space@proxy.example/", "[REDACTED URL]"},
		{"https://example.com/%zz?token=secret", "[REDACTED URL]"},
		{"alice:secret@proxy.example", "[REDACTED URL]"},
		{"%%:alice:secret@proxy.example", "[REDACTED URL]"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := URL(tc.input); got != tc.want {
				t.Errorf("URL(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestError(t *testing.T) {
	_, parseErr := url.Parse("https://alice:sec/ret@proxy.example")
	if parseErr == nil {
		t.Fatal("fixture must produce a URL parse error")
	}
	wrapped := fmt.Errorf("loading proxy configuration: %w", parseErr)
	if got := Error(wrapped); got != `parse "[REDACTED URL]": invalid URL` {
		t.Fatalf("parse error leaked its input: %q", got)
	}
	requestErr := &url.Error{
		Op: "Get", URL: "https://alice:secret@proxy.example/?client_secret=secret",
		Err: errors.New("connection refused"),
	}
	original := requestErr.Error()
	if got := Error(requestErr); got != `Get "https://proxy.example/": connection refused` {
		t.Fatalf("unexpected request error: %q", got)
	}
	wrapped = fmt.Errorf("attempt 2: %w", requestErr)
	if got := Error(wrapped); got != `Get "https://proxy.example/": connection refused` {
		t.Fatalf("unexpected wrapped URL error: %q", got)
	}
	if requestErr.Error() != original {
		t.Fatal("logging mutated the original error")
	}
	if Error(nil) != "" {
		t.Fatal("nil error should be empty")
	}
	for _, value := range []string{
		"dial tcp 127.0.0.1:443: connection refused",
		"retry? See https://example.com/help#timeout",
		"timeout: contact operator@example.com",
	} {
		if got := Error(errors.New(value)); got != value {
			t.Errorf("ordinary error changed: %q", got)
		}
	}
}

func TestBridgePreservesDiagnostics(t *testing.T) {
	logger, records := testlog.New()
	message := "retry? See https://example.com/help#timeout or contact operator@example.com"
	StdLogger(logger).Printf("%s\n", message)

	e := records.LastEntry()
	if e == nil || e.Level != slog.LevelWarn || e.Message != message || e.Data["stdlog"] != "1" {
		t.Fatalf("unexpected bridge record: %+v", e)
	}
}

type reformattedError struct{ cause error }

func (e reformattedError) Error() string {
	return "reformatted credentials: alice=secretA, bob=secretB"
}
func (e reformattedError) Unwrap() error { return e.cause }

func TestJoinedAndReformattedURLErrors(t *testing.T) {
	one := &url.Error{Op: "Get", URL: "https://alice:secretA@one.example/?token=secretA", Err: errors.New("refused")}
	two := &url.Error{Op: "Get", URL: "https://bob:secretB@two.example/", Err: errors.New("timed out")}
	joined := errors.Join(one, fmt.Errorf("attempt 2: %w", two), errors.New("quota exceeded"))
	want := "Get \"https://one.example/\": refused\nGet \"https://two.example/\": timed out\nquota exceeded"
	for _, err := range []error{joined, fmt.Errorf("upstream: %w", joined), reformattedError{joined}} {
		original := err.Error()
		got := Error(err)
		if got != want {
			t.Errorf("unexpected sanitized causes: %q", got)
		}
		if strings.Contains(got, "secret") || err.Error() != original {
			t.Fatal("credentials leaked or original error changed")
		}
	}
	ordinary := fmt.Errorf("retry? %w", errors.Join(errors.New("one failed"), errors.New("two failed")))
	if Error(ordinary) != ordinary.Error() {
		t.Fatal("non-URL error context changed")
	}
}

func TestInstanceDefault(t *testing.T) {
	before := slog.Default()
	a, b := OrDefault(nil), OrDefault(nil)
	if a == b || a == before || slog.Default() != before {
		t.Fatal("default logger is shared or global")
	}
	if _, ok := a.Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("default handler: %T", a.Handler())
	}
	if OrDefault(a) != a {
		t.Fatal("supplied logger replaced")
	}
}
