package smokescreen

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
)

type ConnExt struct {
	net.Conn
	Config *Config
	Role string
	OutboundHost string
	StartTime time.Time

	BytesIn int
	BytesOut int
	Wakeups int

	mutex sync.Mutex
}

func NewConnExt(
	conn net.Conn,
	config *Config, role,
	outboundHost string,
	startTime time.Time) *ConnExt {
	return &ConnExt{
		conn,
		config,
		role,
		outboundHost,
		startTime,
		0,
		0,
		0,
		sync.Mutex{},
	}
}

func (c *ConnExt) Close() error {
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

	c.Config.Log.WithFields(logrus.Fields{
		"bytes_in":    c.BytesIn,
		"bytes_out":   c.BytesOut,
		"role":        c.Role,
		"req_host":    c.OutboundHost,
		"remote_addr": c.Conn.RemoteAddr(),
		"start_time":  c.StartTime.UTC(),
		"end_time":    endTime.UTC(),
		"duration": duration,
		"wakeups": c.Wakeups,
	}).Info("CANONICAL-PROXY-CN-CLOSE")
	return c.Conn.Close()
}

func (c *ConnExt) Read(b []byte) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.BytesIn += len(b)
	c.Wakeups += 1
	return c.Conn.Read(b)
}

func (c *ConnExt) Write(b []byte) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.BytesOut += len(b)
	c.Wakeups += 1
	return c.Conn.Write(b)
}
