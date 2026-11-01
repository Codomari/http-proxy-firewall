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
	cfg, err := config.Load(os.Args[1:], os.Stdout)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	app.New(cfg).Run()
}
