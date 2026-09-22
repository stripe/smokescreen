package smokescreen

import (
	"context"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

type readyListener struct {
	net.Listener
	ready chan struct{}
	once  sync.Once
}

func (l *readyListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}

// Real signals run in a subprocess so tests cannot shut down another proxy.
func TestShutdownLoggingPreservesModes(t *testing.T) {
	if mode := os.Getenv("SMOKESCREEN_TEST_SHUTDOWN"); mode != "" {
		cfg := NewConfig()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		ready := &readyListener{Listener: listener, ready: make(chan struct{})}
		cfg.Listener = ready
		cfg.ExitTimeout = time.Second
		cfg.IdleTimeout = 50 * time.Millisecond
		cfg.ConnTracker = conntrack.NewTracker(cfg.IdleTimeout, cfg.MetricsClient, cfg.ShuttingDown, nil)
		left, right := net.Pipe()
		defer right.Close()
		cfg.ConnTracker.NewInstrumentedConn(context.Background(), left, cfg.Log, "test", "local", "connect", "test")
		quit := make(chan interface{})
		go func() {
			<-ready.ready
			if mode == "graceful" {
				syscall.Kill(os.Getpid(), syscall.SIGTERM)
			} else {
				close(quit)
			}
		}()
		StartWithConfig(cfg, quit)
		return
	}
	for _, mode := range []string{"graceful", "immediate"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownLoggingPreservesModes$")
			cmd.Env = append(os.Environ(), "SMOKESCREEN_TEST_SHUTDOWN="+mode)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", output)
			require.Contains(t, string(output), conntrack.CanonicalProxyConnClose)
			if mode == "graceful" {
				require.Contains(t, string(output), "quitting gracefully")
				require.Contains(t, string(output), "All connections idle: closing all remaining connections.")
			} else {
				require.Contains(t, string(output), "quitting now")
				require.NotContains(t, string(output), "Waiting for all connections")
			}
		})
	}
}
