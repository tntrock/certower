package acme

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/dnsresolver"
	"github.com/tntrock/certower/internal/plugins/cloudflare"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/pkg/plugin"
)

// Live tests talk to real services and run only with CERTOWER_LIVE=1. They
// need no credentials: they create a Let's Encrypt *staging* account, read
// public ARI data, and check that Cloudflare rejects a bogus token.

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("CERTOWER_LIVE") != "1" {
		t.Skip("set CERTOWER_LIVE=1 to run tests against real services")
	}
	s, err := dnsresolver.Configure(nil, dnsresolver.ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DNS resolvers %v, recursive-only %v", s.Servers, s.RecursiveOnly)
}

func configured(t *testing.T, cfg Config) *Issuer {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	iss := &Issuer{}
	if err := iss.Configure(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestLiveStagingAccount(t *testing.T) {
	requireLive(t)
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	a := configured(t, Config{Preset: "letsencrypt-staging", AccountKey: key, AgreeToTerms: true})
	if _, err := a.client(true); err != nil {
		t.Fatalf("register staging account: %v", err)
	}
	if !strings.HasPrefix(a.reg.URI, "https://acme-staging-v02.api.letsencrypt.org/") {
		t.Fatalf("unexpected account URI %q", a.reg.URI)
	}
	t.Logf("registered %s", a.reg.URI)

	b := configured(t, Config{Preset: "letsencrypt-staging", AccountKey: key, AgreeToTerms: true})
	if _, err := b.client(true); err != nil {
		t.Fatal(err)
	}
	if a.reg.URI != b.reg.URI {
		t.Fatalf("same key resolved to a different account: %s vs %s", a.reg.URI, b.reg.URI)
	}
}

func TestLiveARI(t *testing.T) {
	requireLive(t)
	conn, err := tls.Dial("tcp", "letsencrypt.org:443", &tls.Config{ServerName: "letsencrypt.org"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	if !strings.Contains(leaf.Issuer.Organization[0], "Let's Encrypt") {
		t.Skipf("letsencrypt.org is served by %v, not a Let's Encrypt certificate", leaf.Issuer)
	}

	key, _ := GenerateAccountKey()
	iss := configured(t, Config{Preset: "letsencrypt", AccountKey: key, AgreeToTerms: true})
	w, err := iss.RenewalInfo(context.Background(), leaf.Raw)
	if err != nil {
		t.Fatalf("ARI: %v", err)
	}
	if iss.reg != nil {
		t.Error("ARI lookup registered an account")
	}
	if !w.Start.Before(w.End) || w.End.After(leaf.NotAfter) || w.Start.Before(leaf.NotBefore) {
		t.Fatalf("implausible window %s – %s for cert valid %s – %s", w.Start, w.End, leaf.NotBefore, leaf.NotAfter)
	}
	t.Logf("letsencrypt.org cert valid until %s; renew between %s and %s",
		leaf.NotAfter.Format(time.DateOnly), w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
}

func TestLiveCloudflareRejectsBadToken(t *testing.T) {
	requireLive(t)
	s := &cloudflare.Solver{}
	raw, _ := json.Marshal(cloudflare.Config{APIToken: "certower-live-test-invalid-token"})
	if err := s.Configure(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	err := s.Present("certower-test.example.com", "token", "keyauth")
	if err == nil {
		t.Fatal("Cloudflare accepted an invalid token")
	}
	t.Logf("Cloudflare error (expected): %v", err)
}

func TestLiveRejectionIsPermanent(t *testing.T) {
	requireLive(t)
	key, _ := GenerateAccountKey()
	iss := configured(t, Config{Preset: "letsencrypt-staging", AccountKey: key, AgreeToTerms: true})
	k, _ := certutil.GenerateKey(policy.ECDSAP256)
	csr, _ := certutil.CreateCSR(k, []string{"www.example.com"})
	// Let's Encrypt refuses example.com before any challenge is attempted.
	_, err := iss.Issue(context.Background(), plugin.IssueRequest{CSR: csr}, plugin.ChallengeSolvers{DNS: noDNS{}})
	if !errors.Is(err, plugin.ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

type noDNS struct{}

func (noDNS) Meta() plugin.Meta                                { return plugin.Meta{Name: "none", Kind: plugin.KindDNS} }
func (noDNS) Configure(context.Context, json.RawMessage) error { return nil }
func (noDNS) Present(string, string, string) error             { return errors.New("unexpected challenge") }
func (noDNS) CleanUp(string, string, string) error             { return nil }
