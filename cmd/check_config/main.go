package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("missing argument: filePath")
		os.Exit(1)
	}
	filePath := os.Args[1]
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read config file '%s': %v\n", filePath, err)
		os.Exit(1)
	}

	config, err := smokescreen.UnmarshalConfig(bytes)
	if err != nil {
		fmt.Printf("Failed to parse config: %v\n", err);
		os.Exit(1)
	}

	fmt.Printf("Parsed configuration:\n\n%#v\n\n", *config)

	errors := config.Check()
	if len(errors) > 0 {
		fmt.Printf("Check() returned %d error(s):\n\n", len(errors))
		for _, e := range errors {
			fmt.Printf(" - %s\n", e)
		}
		os.Exit(1)
	}

	os.Exit(0)
}
