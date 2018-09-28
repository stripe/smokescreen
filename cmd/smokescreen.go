package cmd

import (
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"

	"github.com/stripe/smokescreen/pkg/smokescreen"
)

// Process command line args into a configuration object.  If the "--help" or
// "--version" flags are provided, return nil with no error.
// If args is nil, os.Args will be used.  If logger is nil, a default logger
// will be created and included in the returned configuration.
func NewConfiguration(args []string, logger *log.Logger) (*smokescreen.Config, error) {
	if args == nil {
		args = os.Args
	}

	var configToReturn *smokescreen.Config

	app := cli.NewApp()
	app.Name = "smokescreen"
	app.Version = smokescreen.Version()
	app.Usage = "A simple HTTP proxy that prevents SSRF and can restrict destinations"
	app.ArgsUsage = " " // blank but non-empty to suppress default "[arguments...]"

	// Suppress "help" subcommand, as we have no other subcommands.
	// Unfortunately, this also suppresses "--help", so we'll add it back in
	// manually below.  See https://github.com/urfave/cli/issues/523
	app.HideHelp = true

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "help",
			Usage: "Show this help text.",
		},
		cli.StringFlag{
			Name:  "listen-ip",
			Usage: "Listen on interface with address `IP`.\n\t\tThis argument is ignored when running under Einhorn. (default: any)",
		},
		cli.IntFlag{
			Name:  "listen-port",
			Value: 4750,
			Usage: "Listen on port `PORT`.\n\t\tThis argument is ignored when running under Einhorn.",
		},
		cli.DurationFlag{
			Name:  "timeout",
			Value: time.Duration(10) * time.Second,
			Usage: "Time out after `DURATION` when connecting.",
		},
		cli.StringFlag{
			Name:  "maintenance-file",
			Usage: "Watch `FILE` for maintenance mode.\n\t\tHTTP(S) requests to /healthcheck return 404 if the file's permissions are set to 000.",
		},
		cli.BoolFlag{
			Name:  "proxy-protocol",
			Usage: "Enable PROXY protocol support.",
		},
		cli.StringSliceFlag{
			Name:  "deny-range",
			Usage: "Add `RANGE`(in CIDR notation) to list of blocked IP ranges.  Repeatable.",
		},
		cli.StringSliceFlag{
			Name:  "allow-range",
			Usage: "Add `RANGE` (in CIDR notation) to list of allowed IP ranges.  Repeatable.",
		},
		cli.StringFlag{
			Name:  "egress-acl-file",
			Usage: "Validate egress traffic against `FILE`",
		},
		cli.StringFlag{
			Name:  "statsd-address",
			Value: "127.0.0.1:8200",
			Usage: "Send metrics to statsd at `ADDRESS` (IP:port).",
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
		cli.StringFlag{
			Name:  "additional-error-message-on-deny",
			Usage: "Display `MESSAGE` in the HTTP response if proxying request is denied",
		},
		cli.StringSliceFlag{
			Name:  "disable-acl-policy-action",
			Usage: "Disable usage of a `POLICY ACTION` such as \"open\" in the egress ACL",
		},
	}

	app.Action = func(c *cli.Context) error {
		if c.Bool("help") {
			cli.ShowAppHelp(c)
			return nil // configToReturn will not be set
		}
		if len(c.Args()) > 0 {
			return errors.New("Received unexpected non-option argument(s)")
		}

		conf := smokescreen.NewConfig()

		if logger != nil {
			conf.Log = logger
		}

		conf.Ip =                           c.String("listen-ip")
		conf.Port = c.Int("listen-port")
		conf.ConnectTimeout = c.Duration("timeout")
		conf.ExitTimeout = 60 * time.Second
		conf.MaintenanceFile = c.String("maintenance-file")
		conf.SupportProxyProtocol = c.Bool("proxy-protocol")
		conf.AdditionalErrorMessageOnDeny = c.String("additional-error-message-on-deny")
		conf.DisabledAclPolicyActions = c.StringSlice("disable-acl-policy-action")

		if err := conf.SetDenyRanges(c.StringSlice("deny-range")); err != nil {
			return err
		}

		if err := conf.SetAllowRanges(c.StringSlice("allow-range")); err != nil {
			return err
		}

		if err := conf.SetupStatsd(c.String("statsd-address")); err != nil {
			return err
		}
		if err := conf.SetupEgressAcl(c.String("egress-acl-file")); err != nil {
			return err
		}
		if err := conf.SetupCrls(c.StringSlice("tls-crl-file")); err != nil {
			return err
		}

		// Originally, we assumed a single file with both cert and key
		// concatenated.  That setup will continue to work, but SetupTLS now
		// takes separate args for cert and key, so we pass the filename twice
		// here.
		bundleFile := c.String("tls-server-bundle-file")
		if bundleFile != "" {
			if err := conf.SetupTls(
				bundleFile,
				bundleFile,
				c.StringSlice("tls-client-ca-file")); err != nil {
				return err
			}
		}

		configToReturn = conf
		return nil
	}

	err := app.Run(args)

	return configToReturn, err
}
