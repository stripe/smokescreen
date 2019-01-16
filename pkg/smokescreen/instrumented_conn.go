package smokescreen

import (
	"net"
)

type ConnExt struct {
	net.Conn
	Config *Config
}

func (c *ConnExt) Close() error {
	c.Config.StatsdClient.Incr("cn.close", []string{}, 1)
	return c.Conn.Close()
}
