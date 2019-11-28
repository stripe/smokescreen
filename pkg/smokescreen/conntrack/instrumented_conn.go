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

type InstrumentedConn struct {
	net.Conn
	Role         string
	OutboundHost string

	tracker *Tracker

	Start        time.Time
	LastActivity *int64 // Unix nano

	BytesIn  *uint64
	BytesOut *uint64

	sync.Mutex

	closed     bool
	CloseError error
}

func (t *Tracker) NewInstrumentedConn(conn net.Conn, role, outboundHost string) *InstrumentedConn {
	now := time.Now().UnixNano()
	bytesIn := uint64(0)
	bytesOut := uint64(0)

	ic := &InstrumentedConn{
		Conn:         conn,
		Role:         role,
		OutboundHost: outboundHost,
		tracker:      t,
		Start:        time.Now(),
		LastActivity: &now,
		BytesIn:      &bytesIn,
		BytesOut:     &bytesOut,
	}

	ic.tracker.Store(ic, nil)
	ic.tracker.Wg.Add(1)

	return ic
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
	}).Info("CANONICAL-PROXY-CN-CLOSE")

	ic.tracker.Wg.Done()

	ic.CloseError = ic.Conn.Close()
	return ic.CloseError
}

func (ic *InstrumentedConn) Read(b []byte) (int, error) {
	atomic.StoreInt64(ic.LastActivity, time.Now().UnixNano())

	n, err := ic.Conn.Read(b)
	atomic.AddUint64(ic.BytesIn, uint64(n))

	return n, err
}

func (ic *InstrumentedConn) Write(b []byte) (int, error) {
	atomic.StoreInt64(ic.LastActivity, time.Now().UnixNano())

	n, err := ic.Conn.Write(b)
	atomic.AddUint64(ic.BytesOut, uint64(n))

	return n, err
}

// Idle returns true when the connection's last activity occured before the
// configured idle threshold.
//
// Idle should be called with the connection's lock held.
func (ic *InstrumentedConn) Idle() bool {
	if time.Since(time.Unix(0, *ic.LastActivity)) > ic.tracker.IdleThreshold {
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
		SecondsSinceLastActivity: time.Now().Sub(time.Unix(0, *ic.LastActivity)).Seconds(),
	}
}

func (ic *InstrumentedConn) JsonStats() ([]byte, error) {
	return json.Marshal(ic.Stats())
}
