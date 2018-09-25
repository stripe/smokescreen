package smokescreen

import "net"

const versionSemantic = "0.0.1"
const versionHash = "$Id$" // See `git help attributes`
func Version() string {
	return versionSemantic + "-" + versionHash[5:13]
}

var privateNetworkStrings = [...]string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

var PrivateNetworkRanges []net.IPNet

func init() {
	PrivateNetworkRanges = make([]net.IPNet, len(privateNetworkStrings))
	for i, s := range privateNetworkStrings {
		_, rng, err := net.ParseCIDR(s)
		if err != nil {
			panic("Couldn't parse internal private network string")
		}
		PrivateNetworkRanges[i] = *rng
	}

}
