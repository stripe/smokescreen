package smokescreen

import (
	"fmt"
	"net"
)

type ipType int

const (
	ipAllowDefault ipType = iota
	ipAllowUserConfigured
	ipDenyNotGlobalUnicast
	ipDenyPrivateRange
	ipDenyUserConfigured
)

func (t ipType) IsAllowed() bool {
	return t == ipAllowDefault || t == ipAllowUserConfigured
}

func (t ipType) String() string {
	switch t {
	case ipAllowDefault:
		return "Allow: Default"
	case ipAllowUserConfigured:
		return "Allow: User Configured"
	case ipDenyNotGlobalUnicast:
		return "Deny: Not Global Unicast"
	case ipDenyPrivateRange:
		return "Deny: Private Range"
	case ipDenyUserConfigured:
		return "Deny: User Configured"
	default:
		panic(fmt.Errorf("unknown ip type %d", t))
	}
}

func (t ipType) statsdString() string {
	switch t {
	case ipAllowDefault:
		return "resolver.allow.default"
	case ipAllowUserConfigured:
		return "resolver.allow.user_configured"
	case ipDenyNotGlobalUnicast:
		return "resolver.deny.not_global_unicast"
	case ipDenyPrivateRange:
		return "resolver.deny.private_range"
	case ipDenyUserConfigured:
		return "resolver.deny.user_configured"
	default:
		panic(fmt.Errorf("unknown ip type %d", t))
	}
}

func classifyAddr(allowRanges, denyRanges []RuleRange, addr *net.TCPAddr) ipType {
	if !addr.IP.IsGlobalUnicast() || addr.IP.IsLoopback() {
		if addrIsInRuleRange(allowRanges, addr) {
			return ipAllowUserConfigured
		} else {
			return ipDenyNotGlobalUnicast
		}
	}

	if addrIsInRuleRange(allowRanges, addr) {
		return ipAllowUserConfigured
	} else if addrIsInRuleRange(denyRanges, addr) {
		return ipDenyUserConfigured
	} else if addrIsInRuleRange(PrivateRuleRanges, addr) {
		return ipDenyPrivateRange
	} else {
		return ipAllowDefault
	}
}

func addrIsInRuleRange(ranges []RuleRange, addr *net.TCPAddr) bool {
	for _, rng := range ranges {
		// If the range specifies a port and the port doesn't match,
		// then this range doesn't match
		if rng.Port != 0 && addr.Port != rng.Port {
			continue
		}

		if rng.Net.Contains(addr.IP) {
			return true
		}
	}
	return false
}
