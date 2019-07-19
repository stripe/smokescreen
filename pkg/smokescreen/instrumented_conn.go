package smokescreen

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type ConnExt struct {
	net.Conn
	Config       *Config
	Role         string
	OutboundHost string
	StartTime    time.Time

	BytesIn      int
	BytesOut     int
	Wakeups      int
	LastActivity time.Time

	mutex sync.Mutex

	isClosed     bool
	errorOnClose error
}

func NewConnExt(
	conn net.Conn,
	config *Config, role,
	outboundHost string,
	startTime time.Time) (ret *ConnExt) {
	ret = &ConnExt{
		conn,
		config,
		role,
		outboundHost,
		startTime,
		0,
		0,
		0,
		time.Now(),
		sync.Mutex{},
		false,
		nil,
	}

	if config.StatsServer != nil {
		config.ConnTracker.Store(ret, nil)
	}

	config.WgCxns.Add(1)

	return
}

// Idle returns true when the connection's last activity occured before the
// configured idle threshold.
//
// Idle should be called with the connection's lock held.
func (c *ConnExt) Idle() bool {
	if time.Since(c.LastActivity) > c.Config.IdleThresholdSec {
		return true
	}
	return false
}

func (c *ConnExt) Close() error {
	if c.isClosed {
		return c.errorOnClose
	}

	c.isClosed = true

	if c.Config.StatsServer != nil {
		c.Config.ConnTracker.Delete(c)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	endTime := time.Now()
	duration := endTime.Sub(c.StartTime).Seconds()

	tags := []string{
		fmt.Sprintf("role:%s", c.Role),
	}

	c.Config.StatsdClient.Incr("cn.close", tags, 1)
	c.Config.StatsdClient.Histogram("cn.duration", duration, tags, 1)
	c.Config.StatsdClient.Histogram("cn.bytes_in", float64(c.BytesIn), tags, 1)
	c.Config.StatsdClient.Histogram("cn.bytes_out", float64(c.BytesOut), tags, 1)

	// This helps us track when we kill active connections during a shutdown
	idle := true
	if c.Config.IsShuttingDown.Load() == true {
		idle = c.Idle()
		if !idle {
			c.Config.StatsdClient.Incr("cn.terminated_active", tags, 1)
		}
	}

	c.Config.Log.WithFields(logrus.Fields{
		"bytes_in":    c.BytesIn,
		"bytes_out":   c.BytesOut,
		"role":        c.Role,
		"req_host":    c.OutboundHost,
		"remote_addr": c.Conn.RemoteAddr(),
		"start_time":  c.StartTime.UTC(),
		"end_time":    endTime.UTC(),
		"duration":    duration,
		"wakeups":     c.Wakeups,
		"idle":        idle,
	}).Info("CANONICAL-PROXY-CN-CLOSE")

	c.Config.WgCxns.Done()

	c.errorOnClose = c.Conn.Close()
	return c.errorOnClose
}

func (c *ConnExt) Read(b []byte) (n int, err error) {
	c.mutex.Lock()
	c.BytesIn += len(b)
	c.Wakeups += 1
	c.LastActivity = time.Now()
	c.mutex.Unlock()

	n, err = c.Conn.Read(b)

	return n, err
}

func (c *ConnExt) Write(b []byte) (n int, err error) {
	c.mutex.Lock()
	c.BytesOut += len(b)
	c.Wakeups += 1
	c.LastActivity = time.Now()
	c.mutex.Unlock()

	n, err = c.Conn.Write(b)

	return n, err
}

func (c *ConnExt) JsonStats() ([]byte, error) {
	type stats = struct {
		Id                       string    `json:"id"`
		Role                     string    `json:"role"`
		Rhost                    string    `json:"rhost"`
		Created                  time.Time `json:"created"`
		BytesIn                  int       `json:"bytesIn"`
		BytesOut                 int       `json:"bytesOut"`
		Wakeups                  int       `json:"wakeups"`
		SecondsSinceLastActivity float64   `json:"secondsSinceLastActivity"`
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	s := stats{
		Id:                       fmt.Sprintf("%d", &c),
		Role:                     c.Role,
		Rhost:                    c.OutboundHost,
		Created:                  c.StartTime,
		BytesIn:                  c.BytesIn,
		BytesOut:                 c.BytesOut,
		Wakeups:                  c.Wakeups,
		SecondsSinceLastActivity: time.Now().Sub(c.LastActivity).Seconds(),
	}

	return json.Marshal(s)
}
