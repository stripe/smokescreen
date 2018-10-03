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

	if config.Port < 1 || config.Port > 65535 {
		fmt.Printf("Invalid port: %d", config.Port)
	}

	os.Exit(0)
}
