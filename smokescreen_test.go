// +build !nounit

package smokescreen

import (
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type testCase struct {
	ip       string
	expected IpType
}

func TestClassifyIP(t *testing.T) {
	cidrWhitelist := []string{
		"8.8.9.0/24",
		"10.0.1.0/24",
		"172.16.1.0/24",
		"192.168.1.0/24",
		"127.0.1.0/24",
	}

	conf, err := NewConfig(
		int(0),
		cidrWhitelist,
		10*time.Second,
		10*time.Second,
		"",
		"",
		"",
		false,
		"",
		nil,
		nil,
		false,
	)
	if err != nil {
		log.Fatal(err)
	}

	testIPs := []testCase{
		// IpTypePublic addresses
		testCase{"8.8.8.8", IpTypePublic},
		// whitelisting a IpTypePublic address does nothing
		testCase{"8.8.9.8", IpTypePublic},

		// Specific blocked networks
		testCase{"10.0.0.1", IpTypePrivate},
		testCase{"10.0.1.1", IpTypeWhitelisted},
		testCase{"172.16.0.1", IpTypePrivate},
		testCase{"172.16.1.1", IpTypeWhitelisted},
		testCase{"192.168.0.1", IpTypePrivate},
		testCase{"192.168.1.1", IpTypeWhitelisted},

		// localhost
		testCase{"127.0.0.1", IpTypePrivate},
		testCase{"127.255.255.255", IpTypePrivate},
		testCase{"::1", IpTypePrivate},
		// whitelisting a localhost address does nothing
		testCase{"127.0.1.1", IpTypePrivate},

		// ec2 metadata endpoint
		testCase{"169.254.169.254", IpTypePrivate},

		// Broadcast addresses
		testCase{"255.255.255.255", IpTypePrivate},
		testCase{"ff02:0:0:0:0:0:0:2", IpTypePrivate},
	}

	for _, test := range testIPs {
		localIP := net.ParseIP(test.ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", test.ip)
			continue
		}

		got := classifyIP(conf, localIP)
		if got != test.expected {
			t.Errorf("Misclassified IP (%s): should be %s, but is instead %s.", localIP, test.expected, got)
		}
	}
}

func TestClearsErrorHeader(t *testing.T) {

	cidrWhitelist := []string{
		"8.8.9.0/24",
		"10.0.1.0/24",
		"172.16.1.0/24",
		"192.168.1.0/24",
		"127.0.1.0/24",
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	conf, err := NewConfig(
		int(39381),
		cidrWhitelist,
		10*time.Second,
		10*time.Second,
		"",
		"",
		"",
		false,
		"",
		nil,
		nil,
		false,
	)
	if err != nil {
		log.Fatal(err)
	}

	proxy := buildProxy(conf)
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
