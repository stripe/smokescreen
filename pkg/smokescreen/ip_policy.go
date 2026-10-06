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

type mostSpecificIPPolicy struct{}

func (mostSpecificIPPolicy) classify(config *Config, addr *net.TCPAddr) ipType {
	bestPrefix, bestPort := -1, false
	result := ipDenyUserConfigured
	for _, rules := range []struct {
		ranges []RuleRange
		action ipType
	}{{config.AllowRanges, ipAllowUserConfigured}, {config.DenyRanges, ipDenyUserConfigured}} {
		for _, rule := range rules.ranges {
			if (rule.Port != 0 && rule.Port != addr.Port) || !rule.Net.Contains(addr.IP) {
				continue
			}
			prefix, bits := rule.Net.Mask.Size()
			// Normalize mapped IPv4 prefixes so equivalent mapped and native rules tie.
			if bits == 128 && rule.Net.IP.To4() != nil && prefix >= 96 {
				prefix -= 96
			}
			port := rule.Port != 0
			if prefix > bestPrefix || (prefix == bestPrefix && port && !bestPort) ||
				(prefix == bestPrefix && port == bestPort && rules.action == ipDenyUserConfigured) {
				bestPrefix, bestPort, result = prefix, port, rules.action
			}
		}
	}
	if bestPrefix >= 0 {
		return result
	}
	if !addr.IP.IsGlobalUnicast() || addr.IP.IsLoopback() {
		return ipDenyNotGlobalUnicast
	}
	return defaultIPClassification(config, addr)
}
