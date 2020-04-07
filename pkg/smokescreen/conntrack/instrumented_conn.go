package conntrack

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const CanonicalProxyConnClose = "CANONICAL-PROXY-CN-CLOSE"

type InstrumentedConn struct {
	net.Conn
	TraceId      string
	Role         string
	OutboundHost string
	proxyType    string
	ConnError    error

	tracker *Tracker

	Start        time.Time
	LastActivity *int64 // Unix nano
	timeout      time.Duration

	BytesIn  *uint64
	BytesOut *uint64

	sync.Mutex

	closed     bool
	CloseError error
}

func (t *Tracker) NewInstrumentedConnWithTimeout(conn net.Conn, timeout time.Duration, traceId, role, outboundHost, proxyType string) *InstrumentedConn {
	ic := t.NewInstrumentedConn(conn, traceId, role, outboundHost, proxyType)
	ic.timeout = timeout
	return ic
}

func (t *Tracker) NewInstrumentedConn(conn net.Conn, traceId, role, outboundHost, proxyType string) *InstrumentedConn {
	now := time.Now()
	nowUnixNano := now.UnixNano()
	bytesIn := uint64(0)
	bytesOut := uint64(0)

	ic := &InstrumentedConn{
		Conn:         conn,
		TraceId:      traceId,
		Role:         role,
		OutboundHost: outboundHost,
		tracker:      t,
		Start:        now,
		LastActivity: &nowUnixNano,
		BytesIn:      &bytesIn,
		BytesOut:     &bytesOut,
	}

	ic.tracker.Store(ic, nil)
	ic.tracker.Wg.Add(1)

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

	end := time.Now()
	duration := end.Sub(ic.Start).Seconds()

	tags := []string{
		fmt.Sprintf("role:%s", ic.Role),
	}

	ic.tracker.statsc.Incr("cn.close", tags, 1)
	ic.tracker.statsc.Histogram("cn.duration", duration, tags, 1)
	ic.tracker.statsc.Histogram("cn.bytes_in", float64(*ic.BytesIn), tags, 1)
	ic.tracker.statsc.Histogram("cn.bytes_out", float64(*ic.BytesOut), tags, 1)

	// Track when we terminate active connections during a shutdown
	idle := true
	if ic.tracker.ShuttingDown.Load() == true {
		idle = ic.Idle()
		if !idle {
			ic.tracker.statsc.Incr("cn.active_at_termination", tags, 1)
		}
	}

	var timeout bool
	var errorMessage string
	if ic.ConnError != nil {
		errorMessage = ic.ConnError.Error()
		if e, ok := ic.ConnError.(net.Error); ok && e.Timeout() {
			timeout = true
			ic.tracker.statsc.Incr("cn.timeout", tags, 1)
		}
	}

	ic.tracker.Log.WithFields(logrus.Fields{
		"idle":        idle,
		"bytes_in":    ic.BytesIn,
		"bytes_out":   ic.BytesOut,
		"role":        ic.Role,
		"req_host":    ic.OutboundHost,
		"remote_addr": ic.Conn.RemoteAddr(),
		"start_time":  ic.Start.UTC(),
		"end_time":    end.UTC(),
		"duration":    duration,
		"timed_out":   timeout,
		"error":       errorMessage,
	}).Info(CanonicalProxyConnClose)

	ic.tracker.Wg.Done()
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
		TraceId:                  ic.TraceId,
		Role:                     ic.Role,
		Rhost:                    ic.OutboundHost,
		Raddr:                    ic.Conn.RemoteAddr().String(),
		Created:                  ic.Start,
		BytesIn:                  *ic.BytesIn,
		BytesOut:                 *ic.BytesOut,
		SecondsSinceLastActivity: time.Now().Sub(time.Unix(0, *ic.LastActivity)).Seconds(),
		ProxyType:                ic.proxyType,
	}
}

func (ic *InstrumentedConn) JsonStats() ([]byte, error) {
	return json.Marshal(ic.Stats())
}
