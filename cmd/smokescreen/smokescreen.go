package main


import (
	"github.com/stripe/smokescreen/pkg/egresswhitelist"
	internal_whitelist "github.com/stripe/smokescreen/internal/pkg/egresswhitelist"
	"gopkg.in/urfave/cli.v1"
	"log"
	"os"
)

func main() {
	
	app := cli.NewApp()
	app.Name = "smokescreen"
	app.Usage = "A simple HTTP proxy that fogs over naughty URLs"
	
	app.Flags = []cli.Flag {
		cli.StringFlag{
			Name: "egress_acl_file",
			Usage: "A file which contains the egress ACL.",
		},
	}
	
	app.Action = func(c *cli.Context) error {
		
		
		var egress_acl *egresswhitelist.EgressWhitelist
		_ = egress_acl
		
		maybe_egress_whitelist_config_path := c.String("egress_acl_file")

		if maybe_egress_whitelist_config_path != "" {
			log.Printf("Loading egress ACL from %s", maybe_egress_whitelist_config_path)
			egress_acl, err := internal_whitelist.LoadFromYaml(maybe_egress_whitelist_config_path)
			
			if err != nil {
				log.Fatal(err)
			}
			
			log.Println(egress_acl)
		}
		
		return nil
	}
	
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
