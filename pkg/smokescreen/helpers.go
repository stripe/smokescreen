package smokescreen

import (
	"net"
)

func AddCidrToSlice(blocks []net.IPNet, cidrBlockString string) ([]net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(cidrBlockString)
	if err != nil {
		return nil, err
	}
	return append(blocks, *ipnet), nil
}
