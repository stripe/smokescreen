package cmd

import (
	smokescreen "github.com/stripe/smokescreen/smoker"
	"gopkg.in/urfave/cli.v1"
	"log"
	"net"
	"os"
	"time"
)

func ConfigFromCli() (*smokescreen.Config, error) {
	return configFromCli(nil)
}

func ConfigFromArgs(args []string) (*smokescreen.Config, error) {
	cwd, _ := os.Getwd()
	return configFromCli(append([]string{cwd}, args...))
}

func configFromCli(args []string) (*smokescreen.Config, error) {

	var configToReturn *smokescreen.Config

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	app := cli.NewApp()
	app.Name = "smokescreen"
	app.Usage = "A simple HTTP proxy that prevents SSRF and can restrict destinations"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "server-ip",
			Usage: "Specify the server's IP",
		},
		cli.IntFlag{
			Name:  "port",
			Value: 4750,
			Usage: "Port to bind on",
		},
		cli.DurationFlag{
			Name:  "timeout",
			Value: time.Duration(10) * time.Second,
			Usage: "Time to wait while connecting",
		},
		cli.StringFlag{
			Name:  "maintenance",
			Usage: "Flag file for maintenance. chmod to 000 to put into maintenance mode",
		},
		cli.BoolFlag{
			Name:  "proxy-protocol",
			Usage: "Enables PROXY protocol support",
		},
		cli.StringSliceFlag{
			Name:  "cidr-blacklist",
			Usage: "CIDR blocks to consider private",
		},
		cli.StringSliceFlag{
			Name:  "cidr-blacklist-exemption",
			Usage: "CIDR block to consider public even if englobing block is found in the blacklist or if IP address is Global Unicast",
		},
		cli.StringFlag{
			Name:  "egress-acl",
			Usage: "A file which contains the egress ACL",
		},
		cli.StringFlag{
			Name:  "statsd-service",
			Value: "127.0.0.1:8200",
			Usage: "IP and port of statsd.",
		},
		cli.StringFlag{
			Name:  "tls-server-pem",
			Usage: "Certificate chain and private key used by the server",
		},
		cli.StringSliceFlag{
			Name:  "tls-client-ca",
			Usage: "Root Certificate Authority used to authenticate clients",
		},
		cli.StringSliceFlag{
			Name:  "crls",
			Usage: "CRL used by the server (reloaded upon change)",
		},
		cli.BoolFlag{
			Name:  "danger-allow-access-to-private-ranges",
			Usage: "WARNING: this will circumvent the check preventing client to reach hosts in private networks. It will make you vulnerable to SSRF.",
		},
		cli.StringFlag{
			Name:  "error-message-on-deny",
			Usage: "Message to return in the HTTP response if proxying request is denied",
		},
	}

	app.Action = func(c *cli.Context) error {

		var err error
		var cidrBlacklist []net.IPNet
		var cidrBlacklistExemptions []net.IPNet

		for _, cidrBlock := range smokescreen.PrivateNetworkStrings {
			cidrBlacklist, err = addCidrToSlice(cidrBlacklist, cidrBlock)
			if err != nil {
				return err
			}
		}

		for _, cidrBlock := range c.StringSlice("cidr-blacklist") {
			cidrBlacklist, err = addCidrToSlice(cidrBlacklist, cidrBlock)
			if err != nil {
				return err
			}
		}

		for _, cidrBlock := range c.StringSlice("cidr-blacklist-exemption") {
			cidrBlacklistExemptions, err = addCidrToSlice(cidrBlacklistExemptions, cidrBlock)
			if err != nil {
				return err
			}
		}

		conf, err := smokescreen.NewConfig(
			c.String("server-ip"),
			c.Int("port"),
			cidrBlacklist,
			cidrBlacklistExemptions,
			c.Duration("timeout"),
			60*time.Second,
			c.String("maintenance"),
			c.String("statsd-service"),
			c.String("egress-acl"),
			c.Bool("proxy-protocol"),
			c.String("tls-server-pem"),
			c.StringSlice("tls-client-ca"),
			c.StringSlice("crls"),
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

func addCidrToSlice(blocks []net.IPNet, cidrBlockString string) ([]net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(cidrBlockString)
	if err != nil {
		return nil, err
	}
	return append(blocks, *ipnet), nil
}
