package smokescreen

import (
	"net"
	"time"
)

type TimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func NewTimeoutConn(conn net.Conn, timeout time.Duration) net.Conn {
	return &TimeoutConn{
		Conn:    conn,
		timeout: timeout,
	}
}

func (tc *TimeoutConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	if err != nil {
		return n, err
	}

	if tc.timeout != 0 {
		err := tc.Conn.SetDeadline(time.Now().Add(tc.timeout))
		if err != nil {
			return 0, err
		}
	}

	return n, nil
}

func (tc *TimeoutConn) Write(b []byte) (int, error) {
	n, err := tc.Conn.Write(b)
	if err != nil {
		return n, err
	}

	if tc.timeout != 0 {
		err := tc.Conn.SetDeadline(time.Now().Add(tc.timeout))
		if err != nil {
			return 0, err
		}
	}

	return n, nil
}
