//go:build !nounit
// +build !nounit

package smokescreen

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShuttingDownValue(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	conf.Port = 39381

	quit := make(chan interface{})
	go StartWithConfig(conf, quit)

	// These sleeps are not ideal, but there is a race with checking the
	// ShuttingDown value from these tests. The server has to bootstrap
	// itself with an initial value before it returns false, and has to
	// set the value to true after we send on the quit channel.
	time.Sleep(500 * time.Millisecond)
	a.Equal(false, conf.ShuttingDown.Load())

	quit <- true

	time.Sleep(500 * time.Millisecond)
	a.Equal(true, conf.ShuttingDown.Load())

}

func TestHealthcheck(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	healthcheckCh := make(chan string)

	testHealthcheck := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
		healthcheckCh <- "OK"
	})

	conf := NewConfig()

	// We set this here so that we can deterministically test the Healthcheck
	// handler. Otherwise we would have to call StartWithConfig() in a goroutine,
	// which creates a race between the test and the listener accepting
	// connections.
	handler := HealthcheckMiddleware{
		Proxy:       BuildProxy(conf),
		Healthcheck: testHealthcheck,
	}

	server := httptest.NewServer(handler)

	errChan := make(chan error, 1)
	go func() {
		select {
		case healthy := <-healthcheckCh:
			if healthy != "OK" {
				errChan <- fmt.Errorf("healthcheck not OK: %s", healthy)
			}
		case <-time.After(5 * time.Second):
			errChan <- errors.New("timed out waiting for client request")
		}
		close(errChan)
	}()

	resp, err := http.Get(fmt.Sprintf("%s/healthcheck", server.URL))
	r.NoError(err)
	a.Equal(http.StatusOK, resp.StatusCode)

	r.NoError(<-errChan)
}
