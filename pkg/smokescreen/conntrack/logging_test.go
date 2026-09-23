package conntrack

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type closeOrderConn struct {
	net.Conn
	close func() error
}

func (c closeOrderConn) Close() error { return c.close() }

func TestCanonicalCloseAndCleanupOrder(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	tracker := NewTestTracker(time.Second)
	var callbackCount, closeCount int
	closeError := errors.New("close failed")
	conn := tracker.NewInstrumentedConn(closeOrderConn{close: func() error {
		closeCount++
		require.Equal(t, 1, callbackCount)
		require.Contains(t, output.String(), CanonicalProxyConnClose)
		// The existing wait-group completion precedes the underlying Close.
		tracker.Wg().Wait()
		return closeError
	}}, logger, "role", "example.com", "connect", "project")
	conn.OnClose = func() {
		callbackCount++
		_, present := tracker.Load(conn)
		require.False(t, present)
		require.Empty(t, output.String())
	}
	atomic.StoreUint64(conn.BytesIn, 123)
	atomic.StoreUint64(conn.BytesOut, 456)
	lastActivity := time.Date(2026, time.September, 22, 12, 34, 56, 123456789, time.UTC)
	atomic.StoreInt64(conn.LastActivity, lastActivity.UnixNano())
	require.ErrorIs(t, conn.Close(), closeError)
	require.ErrorIs(t, conn.Close(), closeError)
	require.Equal(t, 1, callbackCount)
	require.Equal(t, 1, closeCount)
	var record map[string]interface{}
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	require.Equal(t, CanonicalProxyConnClose, record["msg"])
	require.Equal(t, float64(123), record[LogFieldBytesIn])
	require.Equal(t, float64(456), record[LogFieldBytesOut])
	require.Equal(t, "", record[LogFieldError])
	require.Less(t, record[LogFieldDuration].(float64), 1.0)
	require.NotEmpty(t, record[LogFieldEndTime])
	require.Equal(t, lastActivity.Format(time.RFC3339Nano), record[LogFieldLastActivity])
	// Retained output does not change if the counters change later.
	before := output.String()
	atomic.AddUint64(conn.BytesIn, 1)
	require.Equal(t, before, output.String())
}
