package main

import (
	"fmt"
	"os"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("missing argument: filePath")
		os.Exit(1)
	}
	filePath := os.Args[1]
	config, err := smokescreen.LoadConfig(filePath)

	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err);
		os.Exit(1)
	}

	fmt.Printf("Parsed: %#v\n\n", config)

	errors := config.Check()
	if len(errors) > 0 {
		for e := range errors {
			fmt.Println(e)
		}
		os.Exit(1)
	}

	os.Exit(0)
}
