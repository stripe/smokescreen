package smokescreen

import "net"

// Policies read the current configuration on each call. The self-connection
// guard is shared by both policies in classifyAddr.
type allowFirstIPPolicy struct{}

func (allowFirstIPPolicy) classify(config *Config, addr *net.TCPAddr) ipType {
	if !addr.IP.IsGlobalUnicast() || addr.IP.IsLoopback() {
		if addrIsInRuleRange(config.AllowRanges, addr) {
			return ipAllowUserConfigured
		} else {
			return ipDenyNotGlobalUnicast
		}
	}

	if addrIsInRuleRange(config.AllowRanges, addr) {
		return ipAllowUserConfigured
	} else if addrIsInRuleRange(config.DenyRanges, addr) {
		return ipDenyUserConfigured
	}
	return defaultIPClassification(config, addr)
}

func defaultIPClassification(config *Config, addr *net.TCPAddr) ipType {
	if addrHasIPv6Embedding(addr) {
		// Block IPv6 addresses that embed IPv4 addresses (NAT64, 6to4, Teredo, IPv4-mapped)
		// These can bypass IPv4 safety checks and enable SSRF attacks
		return ipDenyIPv6Embedding
	} else if addr.IP.IsPrivate() && !config.UnsafeAllowPrivateRanges {
		return ipDenyPrivateRange
	} else if addrIsCGNAT(addr) {
		return ipDenyCGNAT
	} else {
		return ipAllowDefault
	}
}
