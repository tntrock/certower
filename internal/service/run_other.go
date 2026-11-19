//go:build !windows

package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Run calls run with a context that is cancelled on SIGINT or SIGTERM.
// On Windows it also works as a service; name is the service name there.
func Run(name string, run func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}
