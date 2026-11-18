// Command certower runs the Certower control plane.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tntrock/certower/internal/capresets"
	"github.com/tntrock/certower/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			slog.Error("server stopped", "err", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("certower %s (%s)\n", version.Version, version.Commit)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: certower <command> [flags]

commands:
  serve     run the server
  version   print version`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "address for the API and web UI")
	fs.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"version": version.Version, "commit": version.Commit})
	})
	mux.HandleFunc("GET /api/v1/ca-presets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, capresets.All())
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	slog.Info("certower listening", "addr", *listen, "version", version.Version)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
