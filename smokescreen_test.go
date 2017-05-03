package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIsPrivate(t *testing.T) {
	testIPs := []string{
		// Specific blocked networks
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",

		// localhost
		"127.0.0.1",
		"127.255.255.255",
		"::1",

		// Broadcast addresses
		"255.255.255.255",
		"ff02:0:0:0:0:0:0:2",
	}

	for _, ip := range testIPs {
		localIP := net.ParseIP(ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", ip)
			continue
		}

		if !isPrivateNetwork(localIP) {
			t.Errorf("Local IP (%s) should be private, but isn't", localIP)
		}
	}
}

func TestClearsErrorHeader(t *testing.T) {
	proxy := buildProxy()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	// Create a http.Client that uses our proxy
	client, err := proxyClient(proxySrv.URL)
	if err != nil {
		t.Fatalf("could not build proxy client: %s", err)
	}

	// Talk "through" the proxy to our malicious upstream that sets the
	// error header.
	resp, err := client.Get("http://httpbin.org/response-headers?X-Smokescreen-Error=foobar&X-Smokescreen-Test=yes")
	if err != nil {
		t.Fatalf("could not make request through proxy: %s", err)
	}

	// Should succeed
	if resp.StatusCode != 200 {
		t.Errorf("response had bad status: expected 200, got %d", resp.StatusCode)
	}

	// Verify the error header is not set.
	if h := resp.Header.Get(errorHeader); h != "" {
		t.Errorf("proxy did not strip %q header: %q", errorHeader, h)
	}

	// Verify we did get the other header, to confirm we're talking to the right thing
	if h := resp.Header.Get("X-Smokescreen-Test"); h != "yes" {
		t.Errorf("did not get expected header X-Smokescreen-Test: expected \"yes\", got %q", h)
	}
}

func proxyClient(proxy string) (*http.Client, error) {
	proxyUrl, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}
