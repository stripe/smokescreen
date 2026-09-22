package smokescreen_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

func ExampleConfig_Log() {
	sink := bufio.NewWriter(io.Discard)
	defer sink.Flush() // Runs on normal return, not on fatal os.Exit paths.
	level := new(slog.LevelVar)
	cfg := smokescreen.NewConfig()
	cfg.Log = slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: level}))
	level.Set(slog.LevelDebug)
	cfg.Log.With(slog.String("component", "example")).InfoContext(context.Background(), "configured")
	// Output:
}

func ExampleConfig_Log_redaction() {
	var output bytes.Buffer
	cfg := smokescreen.NewConfig()
	cfg.Log = slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == "trace_id" {
				return slog.String(attr.Key, "[REDACTED]")
			}
			return attr
		},
	}))
	cfg.Log.With(slog.String("trace_id", "client-provided-id")).Info("request", slog.String("proxy_type", "http"))
	var record struct {
		TraceID   string `json:"trace_id"`
		ProxyType string `json:"proxy_type"`
	}
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		panic(err)
	}
	fmt.Println(record.TraceID, record.ProxyType)
	// Output: [REDACTED] http
}

type customACL struct{}

func (customACL) Decide(args acl.DecideArgs) (acl.Decision, error) {
	return acl.Decision{Result: acl.Deny, Reason: "example policy"}, nil
}

var _ acl.Decider = customACL{}

// An embedding can override tracking and still use the standard logging types.
type customTracker struct{ *conntrack.Tracker }

func (t customTracker) NewInstrumentedConnWithTimeout(ctx context.Context, conn net.Conn, timeout time.Duration, logger *slog.Logger, role, host, proxyType, project string) *conntrack.InstrumentedConn {
	return t.Tracker.NewInstrumentedConnWithTimeout(ctx, conn, timeout, logger, role, host, proxyType, project)
}

var _ conntrack.TrackerInterface = customTracker{}
