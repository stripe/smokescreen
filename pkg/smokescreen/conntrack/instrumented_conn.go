package conntrack

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const CanonicalProxyConnClose = "CANONICAL-PROXY-CN-CLOSE"

type InstrumentedConn struct {
	net.Conn
	Role         string
	OutboundHost string
	proxyType    string
	ConnError    error

	tracker *Tracker
	logger  *logrus.Entry

	Start        time.Time
	LastActivity *int64 // Unix nano
	timeout      time.Duration

	BytesIn  *uint64
	BytesOut *uint64

	sync.Mutex

	closed     bool
	CloseError error
}

func (t *Tracker) NewInstrumentedConnWithTimeout(conn net.Conn, timeout time.Duration, logger *logrus.Entry, role, outboundHost, proxyType string) *InstrumentedConn {
	ic := t.NewInstrumentedConn(conn, logger, role, outboundHost, proxyType)
	ic.timeout = timeout
	return ic
}

func (t *Tracker) NewInstrumentedConn(conn net.Conn, logger *logrus.Entry, role, outboundHost, proxyType string) *InstrumentedConn {
	now := time.Now()
	nowUnixNano := now.UnixNano()
	bytesIn := uint64(0)
	bytesOut := uint64(0)

	ic := &InstrumentedConn{
		Conn:         conn,
		Role:         role,
		OutboundHost: outboundHost,
		tracker:      t,
		logger:       logger,
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
	ic.tracker.statsc.Histogram("cn.bytes_in", float64(atomic.LoadUint64(ic.BytesIn)), tags, 1)
	ic.tracker.statsc.Histogram("cn.bytes_out", float64(atomic.LoadUint64(ic.BytesOut)), tags, 1)

	// Track when we terminate active connections during a shutdown
	if ic.tracker.ShuttingDown.Load() == true {
		if !ic.Idle() {
			ic.logger = ic.logger.WithField("active_at_termination", true)
			ic.tracker.statsc.Incr("cn.active_at_termination", tags, 1)
		}
	}

	var errorMessage string
	if ic.ConnError != nil {
		errorMessage = ic.ConnError.Error()
	}

	var dstIP, dstPortStr string
	var dstPort int
	if remoteAddr := ic.Conn.RemoteAddr(); remoteAddr != nil {
		dstIP, dstPortStr, _ = net.SplitHostPort(remoteAddr.String())
		dstPort, _ = strconv.Atoi(dstPortStr)
	}

	ic.logger.WithFields(logrus.Fields{
		"bytes_in":      ic.BytesIn,
		"bytes_out":     ic.BytesOut,
		"role":          ic.Role,
		"end_time":      end.UTC(),
		"duration":      duration,
		"error":         errorMessage,
		"last_activity": time.Unix(0, atomic.LoadInt64(ic.LastActivity)).UTC(),
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
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
