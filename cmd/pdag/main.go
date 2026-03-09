package main

import (
	"fmt"
	"log/slog"
	"os"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: pdag <command> [args]\n")
		fmt.Fprintf(os.Stderr, "commands: serve, key\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(); err != nil {
			slog.Error("fatal", "error", err)
			os.Exit(1)
		}
	case "key":
		if err := runKey(); err != nil {
			slog.Error("fatal", "error", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
