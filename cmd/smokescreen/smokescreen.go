package main

import (
	"github.com/stripe/smokescreen/pkg"
	config "github.com/stripe/smokescreen/pkg/config"
	"gopkg.in/urfave/cli.v1"
	"log"
	"os"
	"strings"
	"time"
)

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	app := cli.NewApp()
	app.Name = "smokescreen"
	app.Usage = "A simple HTTP proxy that fogs over naughty URLs"

	app.Flags = []cli.Flag{
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
		cli.StringFlag{
			Name:  "cidr-whitelist",
			Usage: "Comma-separated list of private address ranges to allow proxying to",
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
	}

	app.Action = func(c *cli.Context) error {

		var whitelistStrings []string
		if len(c.String("cidr-whitelist")) > 0 {
			whitelistStrings = strings.Split(c.String("cidr-whitelist"), ",")
		} else {
			whitelistStrings = nil
		}

		conf, err := config.NewConfig(
			c.Int("port"),
			whitelistStrings,
			c.Duration("timeout"),
			60*time.Second,
			c.String("maintenance"),
			c.String("statsd-service"),
			c.String("egress-acl"),
			c.Bool("proxy-protocol"),
		)
		if err != nil {
			return err
		}

		conf.StatsdClient.Namespace = "smokescreen."

		pkg.StartServer(conf)

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
