package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/discovery"
	"github.com/tntrock/certower/internal/plugins/acme"
	"github.com/tntrock/certower/internal/plugins/cloudflare"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/pkg/plugin"
)

// dev holds developer commands that exercise plugins without a server.
func dev(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return errors.New(`usage: certower dev issue [flags]   (run "certower dev issue -h")`)
	}
	return devIssue(args[1:])
}

func devIssue(args []string) error {
	fs := flag.NewFlagSet("dev issue", flag.ExitOnError)
	preset := fs.String("ca", "letsencrypt-staging", "CA preset (see GET /api/v1/ca-presets)")
	directory := fs.String("directory", "", "ACME directory URL; overrides -ca")
	email := fs.String("email", "", "ACME account contact email")
	domains := fs.String("domains", "", "comma-separated names, e.g. test.example.com,*.example.com (required)")
	keyType := fs.String("key-type", string(policy.ECDSAP256), "certificate key type")
	profile := fs.String("profile", "", "ACME profile, e.g. shortlived")
	out := fs.String("out", "certower-dev", "output directory; the ACME account key is kept here and reused")
	cfTokenEnv := fs.String("cloudflare-token-env", "CLOUDFLARE_API_TOKEN", "environment variable holding the Cloudflare API token")
	eabKID := fs.String("eab-kid", "", "External Account Binding key ID")
	eabHMACEnv := fs.String("eab-hmac-env", "ACME_EAB_HMAC", "environment variable holding the EAB HMAC key")
	dnsOpts := dnsFlags(fs)
	fs.Parse(args)

	names := splitNames(*domains)
	if len(names) == 0 {
		return errors.New("-domains is required")
	}
	cfToken := os.Getenv(*cfTokenEnv)
	if cfToken == "" {
		return fmt.Errorf("set %s to a Cloudflare API token with Zone:Read and DNS:Edit", *cfTokenEnv)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	ctx := context.Background()
	if err := dnsOpts.apply(slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
		return err
	}

	accountKey, err := loadOrCreate(filepath.Join(*out, "account.key"), acme.GenerateAccountKey)
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}
	cfg := acme.Config{
		Preset: *preset, DirectoryURL: *directory, Email: *email,
		AccountKey: accountKey, AgreeToTerms: true, Profile: *profile,
	}
	if *eabKID != "" {
		cfg.EAB = &acme.EAB{KeyID: *eabKID, HMACKey: os.Getenv(*eabHMACEnv)}
	}
	issuer := &acme.Issuer{}
	if err := configure(ctx, issuer, cfg); err != nil {
		return err
	}
	dns := &cloudflare.Solver{}
	if err := configure(ctx, dns, cloudflare.Config{APIToken: cfToken}); err != nil {
		return err
	}

	key, err := certutil.GenerateKey(policy.KeyType(*keyType))
	if err != nil {
		return err
	}
	csr, err := certutil.CreateCSR(key, names)
	if err != nil {
		return err
	}

	fmt.Printf("Requesting %s from %s ...\n", strings.Join(names, ", "), firstNonEmpty(*directory, *preset))
	start := time.Now()
	cert, err := issuer.Issue(ctx, plugin.IssueRequest{CSR: csr}, plugin.ChallengeSolvers{DNS: dns})
	if err != nil {
		return err
	}

	dir := filepath.Join(*out, strings.ReplaceAll(names[0], "*", "_wildcard"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPEM, err := certutil.EncodeKeyPEM(key)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"cert.pem":      certutil.EncodeChainPEM(cert.Chain[:1]),
		"chain.pem":     certutil.EncodeChainPEM(cert.Chain[1:]),
		"fullchain.pem": certutil.EncodeChainPEM(cert.Chain),
		"key.pem":       keyPEM,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}

	parsed, _ := certutil.ParseChainPEM(files["fullchain.pem"])
	leaf := parsed[0]
	fmt.Printf("\nIssued in %s\n", time.Since(start).Round(time.Second))
	fmt.Printf("  Subject:     %s\n", leaf.Subject.CommonName)
	fmt.Printf("  Names:       %s\n", strings.Join(leaf.DNSNames, ", "))
	fmt.Printf("  Issuer:      %s\n", leaf.Issuer.CommonName)
	fmt.Printf("  Valid:       %s to %s (%d days)\n", leaf.NotBefore.Format(time.DateOnly), leaf.NotAfter.Format(time.DateOnly),
		int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24))
	fmt.Printf("  Fingerprint: %s\n", certutil.Fingerprint(leaf.Raw))
	if cert.Renewal != nil {
		fmt.Printf("  Renew (ARI): %s to %s\n", cert.Renewal.Start.Format(time.RFC3339), cert.Renewal.End.Format(time.RFC3339))
	} else {
		fmt.Println("  Renew (ARI): not offered by this CA")
	}
	if fs := discovery.Check(parsed, discovery.Options{}); len(fs) > 0 {
		fmt.Println("  Findings:")
		for _, f := range fs {
			fmt.Printf("    [%s] %s\n", f.Severity, f.Message)
		}
	}
	fmt.Printf("\nFiles written to %s\n", dir)
	return nil
}

func configure(ctx context.Context, p plugin.Plugin, cfg any) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return p.Configure(ctx, raw)
}

func loadOrCreate(path string, gen func() (string, error)) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		return string(b), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	v, err := gen()
	if err != nil {
		return "", err
	}
	return v, os.WriteFile(path, []byte(v), 0o600)
}

func splitNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
