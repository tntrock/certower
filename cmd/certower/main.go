// Command certower runs the Certower control plane.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tntrock/certower/internal/agentapi"
	"github.com/tntrock/certower/internal/agentca"
	"github.com/tntrock/certower/internal/api"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/dnsresolver"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	_ "github.com/tntrock/certower/internal/plugins/all"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/internal/version"
	"github.com/tntrock/certower/pkg/plugin"
	"github.com/tntrock/certower/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "bootstrap":
		err = bootstrap(os.Args[2:])
	case "dev":
		err = dev(os.Args[2:])
	case "version":
		fmt.Printf("certower %s (%s)\n", version.Version, version.Commit)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "certower:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: certower <command> [flags]

commands:
  serve       run the server
  bootstrap   create the first administrator account
  dev issue   issue one certificate from the command line (for testing)
  version     print version

Run "certower <command> -h" for flags.`)
}

// envOr returns the environment variable, or def when unset.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func dbFlag(fs *flag.FlagSet) *string {
	return fs.String("db", envOr("CERTOWER_DB", "sqlite:certower.db"),
		"database: sqlite:<path> or postgres://... (env CERTOWER_DB)")
}

func openStore(ctx context.Context, dsn string) (*store.Store, error) {
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return st, nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", envOr("CERTOWER_LISTEN", ":8080"), "address for the API and web UI (env CERTOWER_LISTEN)")
	dsn := dbFlag(fs)
	kekFile := fs.String("kek-file", envOr("CERTOWER_KEK_FILE", "certower.kek"),
		"key file that encrypts stored secrets; created if missing. Back it up: without it, stored keys and credentials are lost (env CERTOWER_KEK_FILE)")
	workers := fs.Int("workers", 4, "concurrent issuance jobs")
	host, _ := os.Hostname()
	agentListen := fs.String("agent-listen", envOr("CERTOWER_AGENT_LISTEN", ":8443"),
		"address of the agent API (mutual TLS); empty disables agents (env CERTOWER_AGENT_LISTEN)")
	agentURL := fs.String("agent-url", envOr("CERTOWER_AGENT_URL", "https://"+host+":8443"),
		"agent API URL as agents reach it, shown in enrollment commands (env CERTOWER_AGENT_URL)")
	dnsOpts := dnsFlags(fs)
	secure := fs.Bool("secure-cookies", os.Getenv("CERTOWER_SECURE_COOKIES") == "true",
		"mark session cookies Secure; enable behind HTTPS (env CERTOWER_SECURE_COOKIES=true)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := dnsOpts.apply(log); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	if n, err := st.CountUsers(ctx); err == nil && n == 0 {
		log.Warn("no users yet: run \"certower bootstrap -email you@example.com\" to create an administrator")
	}

	kek, created, err := secrets.LoadOrCreateLocalKEK(*kekFile)
	if err != nil {
		return fmt.Errorf("load key file: %w", err)
	}
	if created {
		log.Warn("created a new key-encryption key; back it up, stored secrets cannot be recovered without it", "file", *kekFile)
	}
	vault := &secrets.Vault{Store: st, KEK: kek}
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: plugin.Default}
	eng := &engine.Engine{Store: st, Vault: vault, Configs: configs, Log: log, Workers: *workers}
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		eng.Run(ctx)
	}()
	defer func() { <-engineDone }()

	var agentCA *agentca.CA
	if *agentListen != "" {
		if agentCA, err = agentca.Load(ctx, st, kek); err != nil {
			return fmt.Errorf("agent CA: %w", err)
		}
		agentSrv := &http.Server{
			Addr:              *agentListen,
			Handler:           (&agentapi.Server{Store: st, CA: agentCA, Engine: eng, Log: log}).Handler(),
			TLSConfig:         agentCA.ServerTLSConfig(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Info("agent API listening", "addr", *agentListen, "url", *agentURL, "caSha256", agentCA.Fingerprint())
			if err := agentSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				log.Error("agent API stopped", "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			agentSrv.Close()
		}()
	}

	apiSrv := api.New(api.Deps{Store: st, Log: log, Engine: eng, Configs: configs, Vault: vault, AgentCA: agentCA, AgentURL: *agentURL})
	apiSrv.SecureCookies = *secure
	srv := &http.Server{
		Addr:              *listen,
		Handler:           withUI(apiSrv.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.DeleteExpiredSessions(ctx); err != nil {
					log.Error("session cleanup failed", "err", err)
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	log.Info("certower listening", "addr", *listen, "db", st.Dialect(), "version", version.Version)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func bootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	dsn := dbFlag(fs)
	email := fs.String("email", "", "administrator email (required)")
	fs.Parse(args)
	if !strings.Contains(*email, "@") {
		return errors.New("-email is required")
	}

	ctx := context.Background()
	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	// The password is generated rather than taken as a flag, so it never
	// lands in shell history or process listings.
	b := make([]byte, 18)
	rand.Read(b)
	password := base64.RawURLEncoding.EncodeToString(b)
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	u, err := st.CreateUser(ctx, strings.ToLower(*email), "Administrator", hash, true)
	if errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("user %s already exists", *email)
	} else if err != nil {
		return err
	}
	st.InsertAudit(ctx, store.AuditEntry{ActorType: "system", ActorID: "bootstrap", Action: "user.create", ObjectType: "user", ObjectID: u.ID})

	fmt.Printf("Created administrator %s\nPassword: %s\n\nStore this password now; it is not shown again.\n", u.Email, password)
	return nil
}

type dnsOptions struct {
	servers *string
	mode    *string
}

func dnsFlags(fs *flag.FlagSet) dnsOptions {
	return dnsOptions{
		servers: fs.String("dns-resolvers", os.Getenv("CERTOWER_DNS_RESOLVERS"),
			"comma-separated DNS servers for ACME DNS-01 checks; default: the system's (env CERTOWER_DNS_RESOLVERS)"),
		mode: fs.String("dns-check", envOr("CERTOWER_DNS_CHECK", string(dnsresolver.ModeAuto)),
			"how to confirm DNS-01 records: auto, authoritative, or recursive (env CERTOWER_DNS_CHECK)"),
	}
}

func (o dnsOptions) apply(log *slog.Logger) error {
	s, err := dnsresolver.Configure(splitNames(*o.servers), dnsresolver.Mode(*o.mode), log)
	if err != nil {
		return err
	}
	log.Info("DNS resolvers configured", "servers", s.Servers, "recursiveOnly", s.RecursiveOnly)
	return nil
}

// withUI serves the API under /api/ and /healthz, and the web UI elsewhere.
func withUI(apiHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/healthz", apiHandler)
	mux.Handle("/", web.Handler())
	return mux
}
