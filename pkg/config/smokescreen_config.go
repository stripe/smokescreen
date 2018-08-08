package pkg

import "github.com/DataDog/datadog-go/statsd"
import internal_acl "github.com/stripe/smokescreen/internal/pkg/egressacl"
import "github.com/stripe/smokescreen/pkg/egressacl"
import "net"
import "time"
import "log"

type SmokescreenConfig struct {
	Port                 int
	PrivateNetworks      []net.IPNet
	WhitelistNetworks    []net.IPNet
	ConnectTimeout       time.Duration
	ExitTimeout          time.Duration
	MaintenanceFile      string
	StatsdClient         *statsd.Client
	EgressAcl            egressacl.EgressAcl
	SupportProxyProtocol bool
}

func NewConfig(port int,
	whitelistNetworkStrings []string,
	connectTimeout time.Duration,
	exitTimeout time.Duration,
	maintenanceFile string,
	statsdAddr string,
	egressAclFile string,
	supportProxyProtocol bool,
) (*SmokescreenConfig, error) {

	privateNetworkStrings := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}

	privateNetworks, err := cidrBlocksToIpNets(privateNetworkStrings)
	if err != nil {
		return nil, err
	}

	whitelistNetworks, err := cidrBlocksToIpNets(whitelistNetworkStrings)
	if err != nil {
		return nil, err
	}

	var track *statsd.Client = nil
	if statsdAddr != "" {
		track, err = statsd.New(statsdAddr)
		if err != nil {
			return nil, err
		}
	}

	var egressAcl egressacl.EgressAcl
	if egressAclFile != "" {
		log.Printf("Loading egress ACL from %s", egressAclFile)
		egressAcl, err = internal_acl.LoadFromYamlFile(egressAclFile)

		if err != nil {
			log.Print(err)
		}
	}

	return &SmokescreenConfig{
		Port:                 port,
		PrivateNetworks:      privateNetworks,
		WhitelistNetworks:    whitelistNetworks,
		ConnectTimeout:       connectTimeout,
		ExitTimeout:          exitTimeout,
		MaintenanceFile:      maintenanceFile,
		StatsdClient:         track,
		EgressAcl:            egressAcl,
		SupportProxyProtocol: supportProxyProtocol,
	}, nil

}

func cidrBlocksToIpNets(cidrBlocks []string) ([]net.IPNet, error) {
	nets := make([]net.IPNet, len(cidrBlocks))

	if cidrBlocks == nil {
		return nets, nil
	}

	for i, netstring := range cidrBlocks {
		_, net, err := net.ParseCIDR(netstring)
		if err != nil {
			return nil, err
		}
		nets[i] = *net
	}
	return nets, nil
}
