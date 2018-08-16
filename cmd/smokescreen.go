package main

import (
	"fmt"
	"github.com/stripe/smokescreen"
	"gopkg.in/urfave/cli.v1"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	app := cli.NewApp()
	app.Name = "smokescreen"
	app.Usage = "A simple HTTP proxy that prevents SSRF and can restrict destinations"

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
		cli.StringFlag{
			Name:  "tls-server-pem",
			Value: "/etc/ssl/private/machine.pem",
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
			Name:  "danger-allow-private-ranges",
			Usage: "WARNING: this will circumvent the check preventing client to reach hosts in private networks. It will make you vulnerable to SSRF.",
		},
	}

	app.Action = func(c *cli.Context) error {

		conf, err := smokescreen.NewConfig(
			c.Int("port"),
			splitIfNotEmpty(c.String("cidr-whitelist"), ","),
			c.Duration("timeout"),
			60*time.Second,
			c.String("maintenance"),
			c.String("statsd-service"),
			c.String("egress-acl"),
			c.Bool("proxy-protocol"),
			c.String("tls-server-pem"),
			c.StringSlice("tls-client-ca"),
			c.StringSlice("crls"),
			c.Bool("danger-allow-private-ranges"),
		)
		if err != nil {
			return err
		}

		conf.StatsdClient.Namespace = "smokescreen."

		conf.RoleFromRequest = func(request *http.Request) (string, error) {
			fail := func(err error) (string, error) { return "", err }

			subject := request.TLS.PeerCertificates[0].Subject
			if len(subject.OrganizationalUnit) == 0 {
				fail(fmt.Errorf("warn: Provided cert has no 'OrganizationalUnit'. Can't extract service role."))
			}
			return strings.SplitN(subject.OrganizationalUnit[0], ".", 2)[0], nil
		}

		smokescreen.StartWithConfig(conf)

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func splitIfNotEmpty(in, sep string) []string {
	if in == "" {
		return []string{}
	} else {
		return strings.Split(in, sep)
	}
}
