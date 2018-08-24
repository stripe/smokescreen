package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {

	conf, err := cmd.ConfigFromCli(nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	if conf == nil {
		os.Exit(1)
	}
	smokescreen.StartWithConfig(conf, nil)
}
