package smokescreen

import "net"

const versionSemver = "0.0.1"
const versionHash = "$Id$" // See `git help attributes`
func Version() string {
	return versionSemver + "-" + versionHash[5:13]
}

var PrivateNetworkStrings = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

func PrivateNetworks() []net.IPNet {
	var privateNetworks []net.IPNet
	for _, network := range PrivateNetworkStrings {
		privateNetworks, _ = AddCidrToSlice(privateNetworks, network)
	}
	return privateNetworks
}
