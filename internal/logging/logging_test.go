package logging

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/stripe/smokescreen/internal/testlog"
)

func TestSanitize(t *testing.T) {
	for _, value := range []string{
		"https://alice:secret@proxy.example:443/",
		`parse "https://alice:secret@proxy.example/%zz": invalid URL escape`,
		"https://alice:secret with space@proxy.example/",
		"dial https://alice:secret@proxy.example/?token=secret&x=1",
		"https://example.com/?X-Amz-Signature=secret",
		"https://example.com/?api_key=secret#fragment",
		`parse "%%:alice:secret@proxy.example": invalid URL escape`,
		`parse "alice:secret with space@proxy.example": invalid URL`,
	} {
		if got := Sanitize(value); strings.Contains(got, "secret") || strings.Contains(got, "alice") {
			t.Errorf("unsanitized diagnostic: %q", got)
		}
	}
	if got := URL("alice:secret@host"); got != "[REDACTED URL]" {
		t.Fatal(got)
	}
}

func TestBridgeRedactsBeforeDispatch(t *testing.T) {
	logger, records := testlog.New()
	StdLogger(logger).Printf("dial %s failed", "https://alice:secret@proxy.example/")
	e := records.LastEntry()
	if e == nil || e.Level != slog.LevelWarn || strings.Contains(e.Message, "secret") || e.Data["stdlog"] != "1" {
		t.Fatalf("unexpected bridge record: %+v", e)
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
