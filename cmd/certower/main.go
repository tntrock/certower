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
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/agentapi"
	"github.com/tntrock/certower/internal/agentca"
	"github.com/tntrock/certower/internal/api"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/discovery"
	"github.com/tntrock/certower/internal/dnsresolver"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	_ "github.com/tntrock/certower/internal/plugins/all"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/service"
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
	cfg, args := service.ConfigArg(os.Args[2:])
	if cfg != "" {
		if err := service.LoadEnvFile(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "certower: config:", err)
			os.Exit(1)
		}
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(args)
	case "bootstrap":
		err = bootstrap(args)
	case "healthcheck":
		err = healthcheck(args)
	case "dev":
		err = dev(args)
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
  healthcheck exit 0 if the local server answers (for container health checks)
  dev issue   issue one certificate from the command line (for testing)
  version     print version

Every command also takes -config <file> (or env CERTOWER_CONFIG): a file of
KEY=VALUE lines setting the CERTOWER_* variables the flags read. Real
environment variables take precedence over the file, and flags over both.

Run "certower <command> -h" for flags.`)
}

// envOr returns the environment variable, or def when unset.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envOrEmpty is envOr, except that a variable set to "" counts, so it can
// switch a feature off.
func envOrEmpty(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

// splitList splits a comma-separated list, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
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
	agentListen := fs.String("agent-listen", envOrEmpty("CERTOWER_AGENT_LISTEN", ":8443"),
		"address of the agent API (mutual TLS); empty disables agents (env CERTOWER_AGENT_LISTEN)")
	agentURL := fs.String("agent-url", envOr("CERTOWER_AGENT_URL", "https://"+host+":8443"),
		"agent API URL as agents reach it, shown in enrollment commands (env CERTOWER_AGENT_URL)")
	publicURL := fs.String("public-url", envOr("CERTOWER_PUBLIC_URL", ""),
		"web UI address for links in notifications, e.g. https://certower.example.com (env CERTOWER_PUBLIC_URL)")
	scanLinkLocal := fs.Bool("discovery-allow-link-local", false,
		"let discovery scan link-local addresses such as 169.254.169.254 (off: blocks cloud metadata probing)")
	dnsOpts := dnsFlags(fs)
	secure := fs.Bool("secure-cookies", os.Getenv("CERTOWER_SECURE_COOKIES") == "true",
		"mark session cookies Secure; enable behind HTTPS (env CERTOWER_SECURE_COOKIES=true)")
	trustedProxies := fs.String("trusted-proxies", envOr("CERTOWER_TRUSTED_PROXIES", ""),
		"comma-separated reverse proxy addresses or CIDRs whose X-Forwarded-For is trusted for client addresses (env CERTOWER_TRUSTED_PROXIES)")
	oidcIssuer := fs.String("oidc-issuer", envOr("CERTOWER_OIDC_ISSUER", ""),
		"OpenID Connect issuer URL; enables single sign-on (env CERTOWER_OIDC_ISSUER). The client secret comes from env CERTOWER_OIDC_CLIENT_SECRET")
	oidcClientID := fs.String("oidc-client-id", envOr("CERTOWER_OIDC_CLIENT_ID", ""), "OIDC client ID (env CERTOWER_OIDC_CLIENT_ID)")
	oidcName := fs.String("oidc-name", envOr("CERTOWER_OIDC_NAME", "SSO"), "label on the sign-in button, e.g. Google or Entra ID (env CERTOWER_OIDC_NAME)")
	oidcScopes := fs.String("oidc-scopes", envOr("CERTOWER_OIDC_SCOPES", "openid,email,profile"), "comma-separated scopes to request (env CERTOWER_OIDC_SCOPES)")
	oidcGroups := fs.String("oidc-groups-claim", envOr("CERTOWER_OIDC_GROUPS_CLAIM", "groups"), "ID token claim with the user's groups (env CERTOWER_OIDC_GROUPS_CLAIM)")
	oidcDomains := fs.String("oidc-allowed-domains", envOr("CERTOWER_OIDC_ALLOWED_DOMAINS", ""), "comma-separated email domains allowed to sign in; empty allows any (env CERTOWER_OIDC_ALLOWED_DOMAINS)")
	oidcAutoCreate := fs.Bool("oidc-auto-create", os.Getenv("CERTOWER_OIDC_AUTO_CREATE") == "true",
		"create an account on first sign-in; otherwise users must exist (env CERTOWER_OIDC_AUTO_CREATE=true)")
	oidcSkipVerified := fs.Bool("oidc-insecure-skip-email-verified", false,
		"accept emails the provider does not mark verified; only for providers that omit email_verified but verify addresses")
	logPath := fs.String("log-file", envOr("CERTOWER_LOG_FILE", ""), "append logs to this file instead of stderr (env CERTOWER_LOG_FILE)")
	fs.Parse(args)

	proxies, err := api.ParseTrustedProxies(*trustedProxies)
	if err != nil {
		return fmt.Errorf("-trusted-proxies: %w", err)
	}
	var oidcCfg *api.OIDCConfig
	if *oidcIssuer != "" {
		if *publicURL == "" || *oidcClientID == "" {
			return errors.New("-oidc-issuer needs -public-url and -oidc-client-id")
		}
		oidcCfg = &api.OIDCConfig{
			Issuer:            *oidcIssuer,
			ClientID:          *oidcClientID,
			ClientSecret:      os.Getenv("CERTOWER_OIDC_CLIENT_SECRET"),
			RedirectURL:       strings.TrimSuffix(*publicURL, "/") + "/api/v1/auth/oidc/callback",
			Name:              *oidcName,
			Scopes:            splitList(*oidcScopes),
			GroupsClaim:       *oidcGroups,
			AllowedDomains:    splitList(strings.ToLower(*oidcDomains)),
			AutoCreate:        *oidcAutoCreate,
			SkipEmailVerified: *oidcSkipVerified,
		}
	}
	log, logFile, err := service.Logger(*logPath)
	if err != nil {
		return fmt.Errorf("log file: %w", err)
	}
	defer logFile.Close()
	if err := dnsOpts.apply(log); err != nil {
		return err
	}
	return service.Run("Certower", func(ctx context.Context) error {
		return runServer(ctx, log, serverOptions{
			dsn: *dsn, kekFile: *kekFile, workers: *workers, agentListen: *agentListen, agentURL: *agentURL,
			publicURL: *publicURL, scanLinkLocal: *scanLinkLocal, secure: *secure, proxies: proxies, oidc: oidcCfg, listen: *listen,
		})
	})
}

type serverOptions struct {
	dsn, kekFile, agentListen, agentURL, publicURL, listen string
	workers                                                int
	scanLinkLocal, secure                                  bool
	proxies                                                []netip.Prefix
	oidc                                                   *api.OIDCConfig
}

func runServer(ctx context.Context, log *slog.Logger, o serverOptions) error {

	st, err := openStore(ctx, o.dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	if n, err := st.CountUsers(ctx); err == nil && n == 0 {
		log.Warn("no users yet: run \"certower bootstrap -email you@example.com\" to create an administrator")
	}

	kek, created, err := secrets.LoadOrCreateLocalKEK(o.kekFile)
	if err != nil {
		return fmt.Errorf("load key file: %w", err)
	}
	if created {
		log.Warn("created a new key-encryption key; back it up, stored secrets cannot be recovered without it", "file", o.kekFile)
	}
	vault := &secrets.Vault{Store: st, KEK: kek}
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: plugin.Default}
	eng := &engine.Engine{Store: st, Vault: vault, Configs: configs, Log: log, Workers: o.workers,
		BaseURL: o.publicURL, Scanner: &discovery.Scanner{AllowLinkLocal: o.scanLinkLocal}}
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		eng.Run(ctx)
	}()
	defer func() { <-engineDone }()

	var agentCA *agentca.CA
	if o.agentListen != "" {
		if agentCA, err = agentca.Load(ctx, st, kek); err != nil {
			return fmt.Errorf("agent CA: %w", err)
		}
		agentSrv := &http.Server{
			Addr:              o.agentListen,
			Handler:           (&agentapi.Server{Store: st, CA: agentCA, Engine: eng, Log: log}).Handler(),
			TLSConfig:         agentCA.ServerTLSConfig(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Info("agent API listening", "addr", o.agentListen, "url", o.agentURL, "caSha256", agentCA.Fingerprint())
			if err := agentSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				log.Error("agent API stopped", "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			agentSrv.Close()
		}()
	}

	apiSrv := api.New(api.Deps{Store: st, Log: log, Engine: eng, Configs: configs, Vault: vault, AgentCA: agentCA, AgentURL: o.agentURL, OIDC: o.oidc})
	apiSrv.SecureCookies = o.secure
	apiSrv.TrustedProxies = o.proxies
	srv := &http.Server{
		Addr:              o.listen,
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

	log.Info("certower listening", "addr", o.listen, "db", st.Dialect(), "version", version.Version)
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

// healthcheck asks the local server for /healthz. Container images have no
// curl, so the binary checks itself.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	listen := envOr("CERTOWER_LISTEN", ":8080")
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("CERTOWER_LISTEN: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := fs.String("url", "http://"+net.JoinHostPort(host, port)+"/healthz", "health endpoint")
	fs.Parse(args)
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(*url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", *url, resp.Status)
	}
	return nil
}
