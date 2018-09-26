package smokescreen

import (
	"net"
	"regexp"
)

const versionSemantic = "0.0.1"
const versionHash = "$Id$" // See `git help attributes`
func Version() string {
	return versionSemantic + "-" + versionHash[5:13]
}

const DefaultStatsdNamespace = "smokescreen."

var privateNetworkStrings = [...]string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

var PrivateNetworkRanges []net.IPNet

// Using a globally-shared Regexp can impact performace due to lock contention,
// but calling Copy() for each connection is much worse, and it looks like
// handing out Regexps from a pool doesn't save us anything either, so we'll
// just live with it.
const hostExtractPattern = "^([^:]*)(:\\d+)?$"
var hostExtractRE *regexp.Regexp


func init() {
	PrivateNetworkRanges = make([]net.IPNet, len(privateNetworkStrings))
	for i, s := range privateNetworkStrings {
		_, rng, err := net.ParseCIDR(s)
		if err != nil {
			panic("Couldn't parse internal private network string")
		}
		PrivateNetworkRanges[i] = *rng
	}

	hostExtractRE = regexp.MustCompile(hostExtractPattern)
}
