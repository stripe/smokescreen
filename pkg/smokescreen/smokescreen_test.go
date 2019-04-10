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

	"github.com/stretchr/testify/assert"
)

var allowRanges = []string{
	"8.8.9.0/24",
	"10.0.1.0/24",
	"172.16.1.0/24",
	"192.168.1.0/24",
	"127.0.1.0/24",
}
var allowAddresses = []string{
	"10.0.0.1:321",
}
var denyRanges = []string{
	"1.1.1.1/32",
}
var denyAddresses = []string{
	"8.8.8.8:321",
}

type testCase struct {
	ip       string
	port     int
	expected ipType
}

func TestClassifyAddr(t *testing.T) {
	a := assert.New(t)

	conf := NewConfig()
	a.NoError(conf.SetDenyRanges(denyRanges))
	a.NoError(conf.SetDenyAddresses(denyAddresses))
	a.NoError(conf.SetAllowRanges(allowRanges))
	a.NoError(conf.SetAllowAddresses(allowAddresses))
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"

	testIPs := []testCase{
		testCase{"8.8.8.8", 1, ipAllowDefault},
		testCase{"8.8.9.8", 1, ipAllowUserConfigured},

		// Specific blocked networks
		testCase{"10.0.0.1", 1, ipDenyPrivateRange},
		testCase{"10.0.0.1", 321, ipAllowUserConfigured},
		testCase{"10.0.1.1", 1, ipAllowUserConfigured},
		testCase{"172.16.0.1", 1, ipDenyPrivateRange},
		testCase{"172.16.1.1", 1, ipAllowUserConfigured},
		testCase{"192.168.0.1", 1, ipDenyPrivateRange},
		testCase{"192.168.1.1", 1, ipAllowUserConfigured},
		testCase{"8.8.8.8", 321, ipDenyUserConfigured},
		testCase{"1.1.1.1", 1, ipDenyUserConfigured},

		// localhost
		testCase{"127.0.0.1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"::1", 1, ipDenyNotGlobalUnicast},
		testCase{"127.0.1.1", 1, ipAllowUserConfigured},

		// ec2 metadata endpoint
		testCase{"169.254.169.254", 1, ipDenyNotGlobalUnicast},

		// Broadcast addresses
		testCase{"255.255.255.255", 1, ipDenyNotGlobalUnicast},
		testCase{"ff02:0:0:0:0:0:0:2", 1, ipDenyNotGlobalUnicast},
	}

	for _, test := range testIPs {
		localIP := net.ParseIP(test.ip)
		if localIP == nil {
			t.Errorf("Could not parse IP from string: %s", test.ip)
			continue
		}
		localAddr := net.TCPAddr{
			IP:   localIP,
			Port: test.port,
		}

		got := classifyAddr(conf, &localAddr)
		if got != test.expected {
			t.Errorf("Misclassified IP (%s): should be %s, but is instead %s.", localIP, test.expected, got)
		}
	}
}

func TestClearsErrorHeader(t *testing.T) {
	a := assert.New(t)

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	conf := NewConfig()
	conf.Port = 39381
	a.NoError(conf.SetAllowRanges(allowRanges))
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"

	proxy := BuildProxy(conf)
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
