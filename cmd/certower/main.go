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

	"github.com/tntrock/certower/internal/api"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/internal/version"
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
	secure := fs.Bool("secure-cookies", os.Getenv("CERTOWER_SECURE_COOKIES") == "true",
		"mark session cookies Secure; enable behind HTTPS (env CERTOWER_SECURE_COOKIES=true)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
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

	apiSrv := api.New(st, log)
	apiSrv.SecureCookies = *secure
	srv := &http.Server{
		Addr:              *listen,
		Handler:           apiSrv.Handler(),
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
