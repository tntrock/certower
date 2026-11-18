package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/discovery"
	"github.com/tntrock/certower/internal/dnsresolver"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/testutil/pebble"
	"github.com/tntrock/certower/pkg/plugin"
)

// These tests run against Pebble; see internal/testutil/pebble. They skip
// when Pebble is not installed.

var env *pebble.Env

func TestMain(m *testing.M) {
	code := func() int {
		var stop func()
		var err error
		env, stop, err = pebble.Start()
		if err != nil {
			fmt.Fprintln(os.Stderr, "pebble tests disabled:", err)
		} else {
			defer stop()
		}
		return m.Run()
	}()
	os.Exit(code)
}

func requirePebble(t *testing.T) {
	t.Helper()
	if env == nil {
		t.Skip("pebble not available")
	}
	// Only the mock DNS server knows the challenge records.
	if _, err := dnsresolver.Configure([]string{env.DNSAddr}, dnsresolver.ModeRecursiveOnly, nil); err != nil {
		t.Fatal(err)
	}
}

func newIssuer(t *testing.T, directory string, eab *EAB, profile string) *Issuer {
	t.Helper()
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(Config{
		DirectoryURL:   directory,
		Email:          "test@example.com",
		AccountKey:     key,
		EAB:            eab,
		AgreeToTerms:   true,
		Profile:        profile,
		CACertificates: env.Roots,
	})
	iss := &Issuer{}
	if err := iss.Configure(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return iss
}

func csrFor(t *testing.T, names ...string) []byte {
	t.Helper()
	key, err := certutil.GenerateKey(policy.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certutil.CreateCSR(key, names)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIssueRenewRevoke(t *testing.T) {
	requirePebble(t)
	ctx := context.Background()
	// Pebble picks a random profile when none is requested.
	iss := newIssuer(t, env.PlainURL, nil, "default")
	dns := env.NewChallDNS()

	cert, err := iss.Issue(ctx, plugin.IssueRequest{CSR: csrFor(t, "www.example.com", "*.example.com")}, plugin.ChallengeSolvers{DNS: dns})
	if err != nil {
		t.Fatal(err)
	}
	if dns.Presented() != 2 {
		t.Errorf("presented %d DNS challenges, want 2", dns.Presented())
	}
	if len(cert.Chain) < 2 {
		t.Fatalf("chain has %d certificates, want leaf + intermediate", len(cert.Chain))
	}
	if cert.Renewal == nil || !cert.Renewal.Start.Before(cert.Renewal.End) {
		t.Fatalf("no ARI window: %+v", cert.Renewal)
	}
	parsed, _ := certutil.ParseChainPEM(certutil.EncodeChainPEM(cert.Chain))
	leaf := parsed[0]
	if len(leaf.DNSNames) != 2 {
		t.Errorf("SANs = %v", leaf.DNSNames)
	}
	if fs := discovery.Check(parsed, discovery.Options{}); len(fs) != 0 {
		t.Errorf("fresh certificate has findings: %+v", fs)
	}

	// Renew, telling the CA which certificate is being replaced.
	replaces, err := ARICertID(cert.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := iss.Issue(ctx, plugin.IssueRequest{CSR: csrFor(t, "www.example.com", "*.example.com"), Replaces: replaces}, plugin.ChallengeSolvers{DNS: dns})
	if err != nil {
		t.Fatalf("renewal with replaces: %v", err)
	}
	if bytes.Equal(renewed.Chain[0], cert.Chain[0]) {
		t.Fatal("renewal returned the same certificate")
	}

	if err := iss.Revoke(ctx, cert.Chain[0], 4 /* superseded */); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := iss.Revoke(ctx, cert.Chain[0], 4); err == nil {
		t.Fatal("second revoke succeeded")
	}
}

func TestProfile(t *testing.T) {
	requirePebble(t)
	iss := newIssuer(t, env.PlainURL, nil, "shortlived")
	cert, err := iss.Issue(context.Background(), plugin.IssueRequest{CSR: csrFor(t, "short.example.com")}, plugin.ChallengeSolvers{DNS: env.NewChallDNS()})
	if err != nil {
		t.Fatal(err)
	}
	if life := cert.NotAfter.Sub(cert.NotBefore); life > pebble.ShortLived+time.Minute {
		t.Fatalf("lifetime %s, want about %s from the shortlived profile", life, pebble.ShortLived)
	}
}

func TestExternalAccountBinding(t *testing.T) {
	requirePebble(t)
	ctx := context.Background()
	req := plugin.IssueRequest{CSR: csrFor(t, "eab.example.com")}
	solvers := plugin.ChallengeSolvers{DNS: env.NewChallDNS()}

	if _, err := newIssuer(t, env.EABURL, nil, "").Issue(ctx, req, solvers); err == nil {
		t.Fatal("CA requiring EAB accepted an account without it")
	}
	bad := newIssuer(t, env.EABURL, &EAB{KeyID: pebble.EABKeyID, HMACKey: "d3JvbmcgaG1hYyBrZXkgd3JvbmcgaG1hYyBrZXk"}, "")
	if _, err := bad.Issue(ctx, req, solvers); err == nil {
		t.Fatal("wrong EAB HMAC accepted")
	}
	good := newIssuer(t, env.EABURL, &EAB{KeyID: pebble.EABKeyID, HMACKey: pebble.EABHMAC}, "")
	if _, err := good.Issue(ctx, req, solvers); err != nil {
		t.Fatalf("issue with EAB: %v", err)
	}
}

func TestAccountReuse(t *testing.T) {
	requirePebble(t)
	ctx := context.Background()
	a := newIssuer(t, env.PlainURL, nil, "")
	if _, err := a.client(true); err != nil {
		t.Fatal(err)
	}
	// A second instance with the same key finds the same account.
	b := &Issuer{}
	cfg, _ := json.Marshal(Config{DirectoryURL: env.PlainURL, AccountKey: string(mustPEM(t, a)), AgreeToTerms: true, CACertificates: env.Roots})
	if err := b.Configure(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := b.client(true); err != nil {
		t.Fatal(err)
	}
	if a.reg.URI != b.reg.URI {
		t.Fatalf("account URIs differ: %s vs %s", a.reg.URI, b.reg.URI)
	}
}

func mustPEM(t *testing.T, i *Issuer) []byte {
	t.Helper()
	p, err := certutil.EncodeKeyPEM(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigValidation(t *testing.T) {
	key, _ := GenerateAccountKey()
	cases := map[string]Config{
		"no directory":     {AccountKey: key, AgreeToTerms: true},
		"terms not agreed": {DirectoryURL: "https://acme.example/dir", AccountKey: key},
		"bad key":          {DirectoryURL: "https://acme.example/dir", AccountKey: "nope", AgreeToTerms: true},
		"unknown preset":   {Preset: "nope", AccountKey: key, AgreeToTerms: true},
		"preset needs EAB": {Preset: "zerossl", AccountKey: key, AgreeToTerms: true},
	}
	for name, cfg := range cases {
		raw, _ := json.Marshal(cfg)
		if err := (&Issuer{}).Configure(context.Background(), raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw, _ := json.Marshal(Config{Preset: "letsencrypt-staging", AccountKey: key, AgreeToTerms: true})
	iss := &Issuer{}
	if err := iss.Configure(context.Background(), raw); err != nil || iss.cfg.DirectoryURL == "" {
		t.Errorf("preset not applied: %v %q", err, iss.cfg.DirectoryURL)
	}
	if _, err := iss.Issue(context.Background(), plugin.IssueRequest{CSR: []byte("junk")}, plugin.ChallengeSolvers{}); err == nil {
		t.Error("junk CSR accepted")
	}
}
