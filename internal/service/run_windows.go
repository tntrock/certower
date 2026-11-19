//go:build windows

package service

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"
)

// Run calls run with a context that is cancelled when the process is
// interrupted or, when the Windows service manager started it, when the
// service is stopped. name is the service name.
func Run(name string, run func(ctx context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return run(ctx)
	}
	h := &handler{run: run}
	if err := svc.Run(name, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	run func(ctx context.Context) error
	err error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				h.err = <-done
				return false, 0
			}
		case h.err = <-done:
			// Stopped on its own: report failure so recovery actions apply.
			if h.err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
