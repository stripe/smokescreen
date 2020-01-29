package conntrack

import (
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestInstrumentedConnByteCounting sends a fixed size message between two
// instrumented connections and ensures the bytes in and out are correct.
func TestInstrumentedConnByteCounting(t *testing.T) {
	assert := assert.New(t)

	addr := "localhost:0"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tr := NewTestTracker(0)
	sent := []byte("X-Smokescreen-Test")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}

		icWriter := tr.NewInstrumentedConn(conn, "testid", "test", "localhost", "http")

		n, err := icWriter.Write(sent)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()

		assert.Equal(len(sent), n)
		assert.Equal(uint64(len(sent)), *icWriter.BytesOut)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	icReader := tr.NewInstrumentedConn(conn, "testid", "testBytesInOut", "localhost", "http")

	go func() {
		defer wg.Done()
		read := make([]byte, len(sent))
		for {
			_, err := icReader.Read(read)
			if err != nil {
				if err != io.EOF {
					t.Fatal(err)
				}
				return
			}
			assert.Equal(sent, read)
		}
	}()

	wg.Wait()
	assert.Equal(uint64(len(sent)), *icReader.BytesIn)
}

func TestInstrumentedConnIdle(t *testing.T) {
	assert := assert.New(t)

	tr := NewTestTracker(time.Millisecond)
	ic := tr.NewInstrumentedConn(&net.UnixConn{}, "testid", "testIdle", "localhost", "egress")

	ic.Write([]byte("egress"))
	assert.False(ic.Idle())

	time.Sleep(time.Second)
	assert.True(ic.Idle())
}

var timeoutTests = []struct {
	name          string
	timeout       time.Duration
	expectedError bool
}{
	{"no timeout with zero duration", 0, false},
	{"timeout after duration", 50 * time.Millisecond, true},
}

func TestInstrumentedConnWithTimeout(t *testing.T) {
	addr := "localhost:0"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	handler := func(ln net.Listener) {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		c.Write([]byte("timeout-test"))
		defer c.Close()
	}

	tr := NewTestTracker(0)

	for _, tt := range timeoutTests {
		go handler(ln)

		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}

		var b [1]byte
		ic := tr.NewInstrumentedConnWithTimeout(c, tt.timeout, "", "test", "testHost", "http")

		_, err = ic.Read(b[:])
		if err == nil && tt.expectedError {
			t.Fatalf("%v: expected=%v got=%v", tt.name, tt.expectedError, err)
		}

		if err != nil && !tt.expectedError {
			t.Fatalf("%v: expected=%v got=%v", tt.name, tt.expectedError, err)
		}

		if err != nil {
			if err, ok := err.(net.Error); ok && !err.Timeout() {
				log.Fatal(err)
				t.Fatalf("%v: expected timeout error - got: %v", tt.name, err)
			}
		}
		ic.Close()
	}
}
