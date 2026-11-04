package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Autumn-27/artex/localscan"
)

func runScanCLI(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return localscan.Run(ctx, args, os.Stdout, os.Stderr)
}
