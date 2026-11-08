package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	"http-proxy-firewall/internal/app"
	"http-proxy-firewall/internal/config"
)

func main() {
	os.Exit(run())
}

func run() int {
	// YAML values exported below must not become process overrides on restart.
	processEnvironment := os.Environ()
	if len(os.Args) == 3 && os.Args[1] == "--migrate-config" {
		if err := config.MigrateLegacy(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "configuration migration:", err)
			return 1
		}
		fmt.Println("Legacy configuration migrated to private override YAML and removed.")
		return 0
	}
	cfg, err := config.Load(os.Args[1:], os.Stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		return 1
	}
	if err := cfg.ExportEnvironment(); err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		return 1
	}
	cfg.Runtime.Apply()
	application := app.New(cfg)
	start, cancelStart := context.WithTimeout(context.Background(), 30*time.Second)
	err = application.Start(start)
	cancelStart()
	if err != nil {
		return 1
	}
	signal := <-application.Wait()
	stop, cancelStop := context.WithTimeout(context.Background(), 30*time.Second)
	err = application.Stop(stop)
	cancelStop()
	if err != nil {
		return 1
	}
	if signal.ExitCode == app.RestartExitCode {
		executable, err := os.Executable()
		if err == nil {
			err = syscall.Exec(executable, append([]string{executable}, os.Args[1:]...), processEnvironment)
		}
		fmt.Fprintln(os.Stderr, "restart:", err)
		return 1
	}
	return signal.ExitCode
}
