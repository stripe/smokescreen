package main

import (

	"os"

	cmd "github.com/stripe/smokescreen/cmd"
	smokescreen "github.com/stripe/smokescreen/smoker"
	log "github.com/sirupsen/logrus"
)

func main() {

	conf, err := cmd.ConfigFromCli()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	smokescreen.StartWithConfig(conf, nil)
}
