package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"http-proxy-firewall/internal/app"
	"http-proxy-firewall/internal/config"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--migrate-config" {
		if err := config.MigrateLegacy(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "configuration migration:", err)
			os.Exit(1)
		}
		fmt.Println("Legacy configuration migrated to private override YAML and removed.")
		return
	}
	cfg, err := config.Load(os.Args[1:], os.Stdout)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	if err := cfg.ExportEnvironment(); err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	app.New(cfg).Run()
}
