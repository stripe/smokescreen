package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {

	conf, err := cmd.Configure(nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	if conf == nil {
		log.Fatal("No config")
	}
	smokescreen.StartWithConfig(conf, nil)
}
