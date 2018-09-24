package smokescreen

import (
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type yamlConfig struct{
	Ip string
	Port int
	DenyRanges	[]string `yaml:"deny_ranges"`
	AllowRanges	[]string `yaml:"allow_ranges"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	ExitTimeout time.Duration `yaml:"exit_timeout"`
	MaintenanceFile	string `yaml:"maintenance_file"`
	StatsdAddress string `yaml:"statsd_address"`
	SupportProxyProtocol bool `yaml:"support_proxy_protocol"`
	EgressAclFile string `yaml:"acl_file"`
}

func UnmarshalConfig(rawYaml []byte) (Config, error) {
	var yc yamlConfig
	var c Config
	err := yaml.UnmarshalStrict(rawYaml, &yc)
	if err != nil {
		return c, err
	}

	c.Ip = yc.Ip
	c.Port = yc.Port

	err = c.SetDenyRanges(yc.DenyRanges)
	if err != nil {
		return c, err
	}

	err = c.SetAllowRanges(yc.AllowRanges)
	if err != nil {
		return c, err
	}

	c.ConnectTimeout = yc.ConnectTimeout
	c.ExitTimeout = yc.ExitTimeout

	c.MaintenanceFile = yc.MaintenanceFile
	if c.MaintenanceFile != "" {
		if _, err = os.Stat(c.MaintenanceFile); err != nil {
			return c, err
		}
	}

	err = c.SetupStatsd(yc.StatsdAddress)
	if err != nil {
		return c, err
	}

	c.SupportProxyProtocol = yc.SupportProxyProtocol

	if yc.EgressAclFile != "" {
		err = c.SetupEgressAcl(yc.EgressAclFile)
		if err != nil {
			return c, err
		}
	}

	//TODO TLS server bundle, client ca, crl -> TLS opts

	//TODO disable acl policy?


	return c, nil
}

func LoadConfig(filePath string) (Config, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return Config{}, err
	}
	return UnmarshalConfig(bytes)
}
