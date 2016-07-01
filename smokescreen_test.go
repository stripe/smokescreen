package main

import (
	"net"
	"testing"
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
