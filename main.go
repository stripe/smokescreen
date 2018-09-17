package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {

	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		log.Fatalf("Could not create configuration: %v", err)
	} else if conf != nil {
		smokescreen.StartWithConfig(conf, nil)
	} else {
		// --help or --version was passed and handled by NewConfiguration, so do nothing
	}
}
