package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	cmd "github.com/stripe/smokescreen/cmd"
	smokescreen "github.com/stripe/smokescreen/smoker"
)

func main() {

	conf, err := cmd.ConfigFromCli()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	smokescreen.StartWithConfig(conf, nil)
}
