package main

import (
	"fmt"
	"runtime/debug"
)

// Build metadata, injected at link time via
// -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
// When unset (e.g. `go build` without ldflags), buildInfo falls back to the
// VCS stamps Go embeds when built with buildvcs (the default in a git tree).
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func buildInfo() (v, c, d string) {
	v, c, d = version, commit, date
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			}
		}
	}
	return v, c, d
}

// versionString renders a human-readable build identifier.
func versionString() string {
	v, c, d := buildInfo()
	s := v
	if c != "" {
		short := c
		if len(short) > 12 {
			short = short[:12]
		}
		s += " (" + short + ")"
	}
	if d != "" {
		s += " " + d
	}
	return s
}

func runVersion() error {
	fmt.Println("pdag " + versionString())
	return nil
}
