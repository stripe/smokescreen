package conntrack

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type InstrumentedConn struct {
	net.Conn
	Role         string
	OutboundHost string

	tracker *Tracker

	Start        time.Time
	LastActivity time.Time

	BytesIn  int
	BytesOut int

	sync.Mutex

	closed     bool
	CloseError error
}

func (t *Tracker) NewInstrumentedConn(conn net.Conn, role, outboundHost string) *InstrumentedConn {
	ic := &InstrumentedConn{
		Conn:         conn,
		Role:         role,
		Start:        time.Now(),
		LastActivity: time.Now(),
		tracker:      t,
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
	ic.tracker.statsc.Histogram("cn.bytes_in", float64(ic.BytesIn), tags, 1)
	ic.tracker.statsc.Histogram("cn.bytes_out", float64(ic.BytesOut), tags, 1)

	ic.tracker.Log.WithFields(logrus.Fields{
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

func (ic *InstrumentedConn) Read(b []byte) (n int, err error) {
	ic.Lock()
	ic.BytesIn += len(b)
	ic.LastActivity = time.Now()
	ic.Unlock()

	return ic.Conn.Read(b)
}

func (ic *InstrumentedConn) Write(b []byte) (n int, err error) {
	ic.Lock()
	ic.BytesOut += len(b)
	ic.LastActivity = time.Now()
	ic.Unlock()

	return ic.Conn.Write(b)
}

func (ic *InstrumentedConn) JsonStats() ([]byte, error) {
	type stats = struct {
		Id                       string    `json:"id"`
		Role                     string    `json:"role"`
		Rhost                    string    `json:"rhost"`
		Created                  time.Time `json:"created"`
		BytesIn                  int       `json:"bytesIn"`
		BytesOut                 int       `json:"bytesOut"`
		SecondsSinceLastActivity float64   `json:"secondsSinceLastActivity"`
	}

	ic.Lock()
	defer ic.Unlock()

	s := stats{
		Id:                       fmt.Sprintf("%d", &ic),
		Role:                     ic.Role,
		Rhost:                    ic.OutboundHost,
		Created:                  ic.Start,
		BytesIn:                  ic.BytesIn,
		BytesOut:                 ic.BytesOut,
		SecondsSinceLastActivity: time.Now().Sub(ic.LastActivity).Seconds(),
	}

	return json.Marshal(s)
}
