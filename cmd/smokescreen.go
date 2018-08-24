package cmd

import (
	"github.com/stripe/smokescreen/pkg/smokescreen"
	"gopkg.in/urfave/cli.v1"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func ConfigFromCli(logger *log.Logger) (*smokescreen.Config, error) {
	return configFromCli(logger, nil)
}

func ConfigFromArgs(logger *log.Logger, args []string) (*smokescreen.Config, error) {
	return configFromCli(logger, append([]string{os.Args[0]}, args...))
}

func configFromCli(logger *log.Logger, args []string) (*smokescreen.Config, error) {

	var configToReturn *smokescreen.Config

	app := cli.NewApp()
	app.Name = "smokescreen"
	app.Usage = "A simple HTTP proxy that prevents SSRF and can restrict destinations"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "server-ip",
			Usage: "Binds on interface with `ip`",
		},
		cli.IntFlag{
			Name:  "server-port",
			Value: 4750,
			Usage: "Binds on `port`",
		},
		cli.DurationFlag{
			Name:  "timeout",
			Value: time.Duration(10) * time.Second,
			Usage: "Waits `duration` when connecting",
		},
		cli.StringFlag{
			Name:  "maintenance-file",
			Usage: "Chmod `file` to 000 to put into maintenance mode",
		},
		cli.BoolFlag{
			Name:  "proxy-protocol",
			Usage: "Enable PROXY protocol support",
		},
		cli.StringSliceFlag{
			Name:  "blacklist",
			Usage: "`CIDR block` to consider private",
		},
		cli.StringSliceFlag{
			Name:  "blacklist-exemption",
			Usage: "`CIDR block` to consider public even if englobing block is found in the blacklist or if IP address is Global Unicast",
		},
		cli.StringFlag{
			Name:  "egress-acl-file",
			Usage: "Validate egress traffic against `file`",
		},
		cli.StringFlag{
			Name:  "statsd",
			Value: "127.0.0.1:8200",
			Usage: "`IP:port` to statsd",
		},
		cli.StringFlag{
			Name:  "tls-server-bundle-file",
			Usage: "Authenticate to clients using key and certs from `FILE`",
		},
		cli.StringSliceFlag{
			Name:  "tls-client-ca-file",
			Usage: "Validate client certificates using Certificate Authority from `FILE`",
		},
		cli.StringSliceFlag{
			Name:  "tls-crl-file",
			Usage: "Verify validity of client certificates against Certificate Revocation List from `FILE`",
		},
		cli.BoolFlag{
			Name:  "danger-allow-access-to-private-ranges",
			Usage: "WARNING: circumvent the check preventing client to reach hosts in private networks - It will make you vulnerable to SSRF.",
		},
		cli.StringFlag{
			Name:  "error-message-on-deny",
			Usage: "Display `MESSAGE` in the HTTP response if proxying request is denied",
		},
	}

	app.Action = func(c *cli.Context) error {

		var err error
		var cidrBlacklist []net.IPNet
		var cidrBlacklistExemptions []net.IPNet

		for _, cidrBlock := range smokescreen.PrivateNetworkStrings {
			cidrBlacklist, err = smokescreen.AddCidrToSlice(cidrBlacklist, cidrBlock)
			if err != nil {
				return err
			}
		}

		for _, cidrBlock := range c.StringSlice("cidr-blacklist") {
			cidrBlacklist, err = smokescreen.AddCidrToSlice(cidrBlacklist, cidrBlock)
			if err != nil {
				return err
			}
		}

		for _, cidrBlock := range c.StringSlice("cidr-blacklist-exemption") {
			cidrBlacklistExemptions, err = smokescreen.AddCidrToSlice(cidrBlacklistExemptions, cidrBlock)
			if err != nil {
				return err
			}
		}

		conf, err := smokescreen.NewConfig(
			logger,
			c.String("server-ip"),
			c.Int("server-port"),
			cidrBlacklist,
			cidrBlacklistExemptions,
			c.Duration("timeout"),
			60*time.Second,
			c.String("maintenance-file"),
			c.String("statsd"),
			c.String("egress-acl-file"),
			c.Bool("proxy-protocol"),
			c.String("tls-server-bundle-file"),
			c.StringSlice("tls-client-ca-file"),
			c.StringSlice("tls-crl-file"),
			c.Bool("danger-allow-access-to-private-ranges"),
			c.String("error-message-on-deny"),
		)
		if err != nil {
			return err
		}

		conf.StatsdClient.Namespace = "smokescreen."

		configToReturn = conf
		return nil
	}

	var err error
	if args == nil {
		err = app.Run(os.Args)
	} else {
		err = app.Run(args)
	}

	return configToReturn, err
}
