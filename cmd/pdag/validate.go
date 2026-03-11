package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mai/pdag/internal/config"
)

func runValidate() error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	_ = fs.Parse(os.Args[2:])

	if _, err := config.Load(*configPath); err != nil {
		return err
	}

	fmt.Println("config OK")
	return nil
}
