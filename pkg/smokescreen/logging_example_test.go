package smokescreen_test

import (
	"bufio"
	"context"
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
	defer sink.Flush() // Caller owns cleanup, after the proxy finishes.
	level := new(slog.LevelVar)
	cfg := smokescreen.NewConfig()
	cfg.Log = slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: level}))
	level.Set(slog.LevelDebug)
	cfg.Log.With(slog.String("component", "example")).InfoContext(context.Background(), "configured")
	// Output:
}

func ExampleConfig_LoadFile() {
	cfg := smokescreen.NewConfig()
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	// Set the logger before loading a real configuration file:
	// err := cfg.LoadFile("smokescreen.yaml")
	_ = cfg
	// Output:
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
