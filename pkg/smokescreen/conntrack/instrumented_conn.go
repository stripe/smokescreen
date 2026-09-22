package conntrack

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stripe/smokescreen/internal/logging"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

const (
	LogFieldBytesIn         = "bytes_in"
	LogFieldBytesOut        = "bytes_out"
	LogFieldEndTime         = "end_time"
	LogFieldDuration        = "duration"
	LogFieldError           = "error"
	LogFieldLastActivity    = "last_activity"
	CanonicalProxyConnClose = "CANONICAL-PROXY-CN-CLOSE"
)

type InstrumentedConn struct {
	net.Conn
	Role         string
	Project      string
	OutboundHost string
	proxyType    string
	ConnError    error

	tracker *Tracker
	logger  *slog.Logger
	ctx     context.Context

	Start        time.Time
	LastActivity *int64 // Unix nano
	timeout      time.Duration

	BytesIn  *uint64
	BytesOut *uint64

	sync.Mutex

	closed     bool
	CloseError error

	// OnClose is called when the connection is closed.
	// This can be used to release resources like tunnel limiter slots.
	OnClose func()
}

// NewInstrumentedConnWithTimeout retains ctx for logging only; timeout controls I/O deadlines.
func (t *Tracker) NewInstrumentedConnWithTimeout(ctx context.Context, conn net.Conn, timeout time.Duration, logger *slog.Logger, role, outboundHost, proxyType, project string) *InstrumentedConn {
	ic := t.NewInstrumentedConn(ctx, conn, logger, role, outboundHost, proxyType, project)
	ic.timeout = timeout
	return ic
}

// NewInstrumentedConn retains ctx for close diagnostics, even after cancellation.
// Canceling ctx does not close the connection. Nil context uses context.Background.
func (t *Tracker) NewInstrumentedConn(ctx context.Context, conn net.Conn, logger *slog.Logger, role, outboundHost, proxyType, project string) *InstrumentedConn {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	nowUnixNano := now.UnixNano()
	bytesIn := uint64(0)
	bytesOut := uint64(0)

	ic := &InstrumentedConn{
		Conn:         conn,
		Role:         role,
		Project:      project,
		OutboundHost: outboundHost,
		tracker:      t,
		logger:       logging.OrDefault(logger),
		ctx:          ctx,
		Start:        now,
		LastActivity: &nowUnixNano,
		BytesIn:      &bytesIn,
		BytesOut:     &bytesOut,
	}

	ic.tracker.Store(ic, nil)
	ic.tracker.Wg().Add(1)

	return ic
}

func (ic *InstrumentedConn) Error(err error) {
	ic.ConnError = err
}

func (ic *InstrumentedConn) Close() error {
	ic.Lock()
	defer ic.Unlock()

	if ic.closed {
		return ic.CloseError
	}

	ic.closed = true
	ic.tracker.Delete(ic)

	// Call OnClose callback if set (e.g., to release tunnel limiter slot)
	if ic.OnClose != nil {
		ic.OnClose()
	}

	end := time.Now()
	duration := end.Sub(ic.Start).Seconds()

	tags := map[string]string{
		"role":    metrics.SanitizeTagValue(ic.Role),
		"project": metrics.SanitizeTagValue(ic.Project),
	}

	ic.tracker.statsc.IncrWithTags("cn.close", tags, 1)
	ic.tracker.statsc.HistogramWithTags("cn.duration", duration, tags, 1)
	ic.tracker.statsc.HistogramWithTags("cn.bytes_in", float64(atomic.LoadUint64(ic.BytesIn)), tags, 1)
	ic.tracker.statsc.HistogramWithTags("cn.bytes_out", float64(atomic.LoadUint64(ic.BytesOut)), tags, 1)

	// Track when we terminate active connections during a shutdown
	if ic.tracker.ShuttingDown.Load() == true {
		if !ic.Idle() {
			ic.logger = ic.logger.With("active_at_termination", true)
			ic.tracker.statsc.IncrWithTags("cn.active_at_termination", tags, 1)
		}
	}

	var errorMessage string
	if ic.ConnError != nil {
		errorMessage = logging.Sanitize(ic.ConnError.Error())
	}

	ic.logger.With(slog.Uint64(LogFieldBytesIn, atomic.LoadUint64(ic.BytesIn)),
		slog.Uint64(LogFieldBytesOut, atomic.LoadUint64(ic.BytesOut)),
		slog.Time(LogFieldEndTime, end.UTC()),
		slog.Float64(LogFieldDuration, duration),
		slog.String(LogFieldError, errorMessage),
		slog.Time(LogFieldLastActivity, time.Unix(0, atomic.LoadInt64(ic.LastActivity)).UTC())).InfoContext(ic.ctx, CanonicalProxyConnClose)

	ic.tracker.Wg().Done()
	ic.CloseError = ic.Conn.Close()
	return ic.CloseError
}

func (ic *InstrumentedConn) Read(b []byte) (int, error) {
	now := time.Now()
	if ic.timeout != 0 {
		if err := ic.Conn.SetDeadline(now.Add(ic.timeout)); err != nil {
			return 0, err
		}
	}

	atomic.StoreInt64(ic.LastActivity, now.UnixNano())

	n, err := ic.Conn.Read(b)
	atomic.AddUint64(ic.BytesIn, uint64(n))

	return n, err
}

func (ic *InstrumentedConn) Write(b []byte) (int, error) {
	now := time.Now()
	if ic.timeout != 0 {
		if err := ic.Conn.SetDeadline(now.Add(ic.timeout)); err != nil {
			return 0, err
		}
	}

	atomic.StoreInt64(ic.LastActivity, now.UnixNano())

	n, err := ic.Conn.Write(b)
	atomic.AddUint64(ic.BytesOut, uint64(n))

	return n, err
}

// Idle returns true when the connection's last activity occured before the
// configured idle threshold.
//
// Idle should be called with the connection's lock held.
func (ic *InstrumentedConn) Idle() bool {
	if ic.tracker.IdleTimeout == 0 {
		return false
	}

	if time.Since(time.Unix(0, *ic.LastActivity)) > ic.tracker.IdleTimeout {
		return true
	}
	return false
}

func (ic *InstrumentedConn) Stats() *InstrumentedConnStats {
	ic.Lock()
	defer ic.Unlock()

	return &InstrumentedConnStats{
		Role:                     ic.Role,
		Rhost:                    ic.OutboundHost,
		Raddr:                    ic.Conn.RemoteAddr().String(),
		Created:                  ic.Start,
		BytesIn:                  *ic.BytesIn,
		BytesOut:                 *ic.BytesOut,
		SecondsSinceLastActivity: time.Since(time.Unix(0, *ic.LastActivity)).Seconds(),
		ProxyType:                ic.proxyType,
	}
}

func (ic *InstrumentedConn) JsonStats() ([]byte, error) {
	return json.Marshal(ic.Stats())
}
