//go:build !nounit
// +build !nounit

package smokescreen

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

func findCanonicalProxyDecision(logs []*logrus.Entry) *logrus.Entry {
	for _, entry := range logs {
		if entry.Message == CanonicalProxyDecision {
			return entry
		}
	}
	return nil
}

func findCanonicalProxyClose(logs []*logrus.Entry) *logrus.Entry {
	for _, entry := range logs {
		if entry.Message == conntrack.CanonicalProxyConnClose {
			return entry
		}
	}
	return nil
}

func testConfig(role string) (*Config, error) {
	conf := NewConfig()

	if err := conf.SetAllowRanges(allowRanges); err != nil {
		return nil, err
	}
	conf.ConnectTimeout = 10 * time.Second
	conf.ExitTimeout = 10 * time.Second
	conf.AdditionalErrorMessageOnDeny = "Proxy denied"
	conf.Resolver = &net.Resolver{}
	conf.SetupEgressAcl("testdata/acl.yaml")
	conf.RoleFromRequest = func(req *http.Request) (string, error) {
		return role, nil
	}

	mc := metrics.NewMockMetricsClient()
	conf.ConnTracker = conntrack.NewTracker(conf.IdleTimeout, mc, conf.Log, atomic.Value{}, nil)
	conf.MetricsClient = mc
	return conf, nil
}

func proxyLogHook(conf *Config) *logrustest.Hook {
	var testHook logrustest.Hook
	conf.Log.AddHook(&testHook)
	return &testHook
}

func proxyServer(conf *Config) *httptest.Server {
	proxy := BuildProxy(conf)
	return httptest.NewServer(proxy)
}

func proxyClient(proxy string) (*http.Client, error) {
	return proxyClientWithConnectHeaders(proxy, nil)
}

func proxyClientWithConnectHeaders(proxy string, proxyConnectHeaders http.Header) (*http.Client, error) {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ProxyConnectHeader:    proxyConnectHeaders,
		},
	}, nil
}
