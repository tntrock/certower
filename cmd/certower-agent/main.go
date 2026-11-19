// Command certower-agent runs on hosts. It keeps private keys on the host,
// asks the Certower server for certificates, and installs them into local
// services.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/tntrock/certower/internal/agent"
	"github.com/tntrock/certower/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "version":
		fmt.Printf("certower-agent %s (%s)\n", version.Version, version.Commit)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "certower-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: certower-agent <command> [flags]

commands:
  enroll    register with a server using a one-time token
  run       sync with the server and install certificates
  version   print version

Run "certower-agent <command> -h" for flags.`)
}

func defaultStateDir() string {
	if v := os.Getenv("CERTOWER_AGENT_STATE"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Certower", "agent")
	}
	return "/var/lib/certower-agent"
}

// listFlag collects a repeated flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "agent API URL, e.g. https://certower.example.com:8443 (required)")
	token := fs.String("token", "", "one-time enrollment token (required)")
	caSHA := fs.String("ca-sha256", "", "SHA-256 fingerprint of the server's agent CA (required)")
	state := fs.String("state", defaultStateDir(), "state directory (env CERTOWER_AGENT_STATE)")
	var paths listFlag
	fs.Var(&paths, "allow-path", "directory certificates may be written under (repeatable; default "+strings.Join(agent.DefaultAllowedPaths(), ", ")+")")
	fs.Parse(args)
	if *server == "" || *token == "" || *caSHA == "" {
		return fmt.Errorf("-server, -token and -ca-sha256 are required (the server shows the full command when you create an agent)")
	}
	opts := agent.EnrollOptions{Server: *server, Token: *token, CASHA256: *caSHA, StateDir: *state}
	if len(paths) > 0 {
		opts.AllowedPaths = paths
	}
	cfg, err := agent.Enroll(context.Background(), opts)
	if err != nil {
		return err
	}
	fmt.Printf("Enrolled as agent %s.\nState: %s\nAllowed paths: %s\n\nReview allowedPaths and allowedCommands in %s, then start \"certower-agent run\".\n",
		cfg.AgentID, *state, strings.Join(cfg.AllowedPaths, ", "), filepath.Join(*state, "agent.json"))
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	state := fs.String("state", defaultStateDir(), "state directory (env CERTOWER_AGENT_STATE)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a, err := agent.Open(*state, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}
