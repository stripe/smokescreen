// +build integration

package main

import "github.com/stretchr/testify/assert"
import (
	"testing"
	"github.com/stripe/smokescreen"
	"net/http"
	"io"
	"net"
	"io/ioutil"
	"fmt"
	"syscall"
)

type DummyHandler struct {}
func (s *DummyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
		io.WriteString(rw, "ok")
}

func NewDummyServer() *http.Server {
	return &http.Server{
		Handler: &DummyHandler{},
	}
}


func TestSmokescreenNoTls(t *testing.T) {
	a := assert.New(t)

	dummyServer := NewDummyServer()
	outsideListener, err := net.Listen("tcp4", "127.0.0.1:")
	go dummyServer.Serve(outsideListener)

	conf, err := ConfigFromArgs([]string{
		"--server-ip=127.0.0.1",
		"--port=4520",
		"--egress-acl=testdata/sample_config.yaml",
		"--danger-allow-access-to-private-ranges",
		"--error-message-on-deny=\"egress denied: go see doc at https://example.com/egressproxy\"",
	})
	a.NoError(err)
	kill := make(chan interface{})
	go smokescreen.StartWithConfig(conf, kill)
	defer func() {kill <- syscall.SIGHUP}()

	client := http.Client{}

	resp, err := client.Get("http://" + outsideListener.Addr().String())
	a.NoError(err)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	// Can we reach the target server?
	a.Equal("ok", string(bodyBytes))
	// At this point, we know that the dummy server is up

	/*
	proxyUrl, err := url.Parse("http://127.0.0.1:4520")
	a.NoError(err)


	client = http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
	}
	*/

	// Let's make a request with an unknown role
	req, err := http.NewRequest("GET", "http://127.0.0.1:4520", nil)
	a.NoError(err)
	req.Host = outsideListener.Addr().String()
	req.Header.Add("X-Smokescreen-Role", "unknown-service-111222333")
	resp, err = client.Do(req)
	fmt.Println(err)
	a.NoError(err)
	a.Equal(503, resp.StatusCode)

	// Let's talk to a host we're allowed to talk with
	req, err = http.NewRequest("GET", "http://127.0.0.1:4520", nil)
	a.NoError(err)
	req.Host = outsideListener.Addr().String()
	req.Header.Add("X-Smokescreen-Role", "egressneedingservice")
	resp, err = client.Do(req)
	a.NoError(err)
	a.Equal(200, resp.StatusCode)
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	a.Equal("ok", string(bodyBytes))

	// Let's talk to a host we're not allowed to talk with
	req, err = http.NewRequest("GET", "http://127.0.0.1:4520", nil)
	a.NoError(err)
	req.Host = "stripe.com"
	req.Header.Add("X-Smokescreen-Role", "egressneedingservice")
	resp, err = client.Do(req)
	a.NoError(err)
	a.Equal(503, resp.StatusCode)

	// Let's talk to a host we're not allowed to talk with - in reporting mode
	req, err = http.NewRequest("GET", "http://127.0.0.1:4520", nil)
	a.NoError(err)
	req.Host = "stripe.com"
	req.Header.Add("X-Smokescreen-Role", "egressneedingservice-report")
	resp, err = client.Do(req)
	a.NoError(err)
	a.Equal(200, resp.StatusCode)

	// Let's talk to a host we're not allowed to talk with - in open mode
	req, err = http.NewRequest("GET", "http://127.0.0.1:4520", nil)
	a.NoError(err)
	req.Host = "stripe.com"
	req.Header.Add("X-Smokescreen-Role", "egressneedingservice-open")
	resp, err = client.Do(req)
	a.NoError(err)
	a.Equal(200, resp.StatusCode)

}
