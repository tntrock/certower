package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/discovery"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/pkg/plugin"
)

// These tests run against Pebble, Let's Encrypt's ACME test server, and
// pebble-challtestsrv, its mock DNS server. Install them with
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//
// The tests skip when the binaries are not on PATH or in $GOPATH/bin.

const (
	dnsAddr     = "127.0.0.1:18053"
	challMgmt   = "127.0.0.1:18055"
	eabKeyID    = "kid-1"
	eabHMAC     = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
	shortLived  = 6 * 24 * time.Hour
	waitTimeout = 15 * time.Second
)

type pebbleEnv struct {
	plainURL string // no EAB
	eabURL   string // EAB required
	roots    string // PEM trusted for Pebble's TLS
}

var env *pebbleEnv

func TestMain(m *testing.M) {
	code := func() int {
		var cleanup func()
		var err error
		env, cleanup, err = startPebble()
		if err != nil {
			fmt.Fprintln(os.Stderr, "pebble tests disabled:", err)
		}
		if cleanup != nil {
			defer cleanup()
		}
		return m.Run()
	}()
	os.Exit(code)
}

func findBinary(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	gopath, err := exec.Command("go", "env", "GOPATH").Output()
	if err == nil {
		p := filepath.Join(string(bytes.TrimSpace(gopath)), "bin", name)
		if _, err := exec.LookPath(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

func startPebble() (*pebbleEnv, func(), error) {
	pebble, err := findBinary("pebble")
	if err != nil {
		return nil, nil, err
	}
	chall, err := findBinary("pebble-challtestsrv")
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "certower-pebble")
	if err != nil {
		return nil, nil, err
	}
	td, _ := filepath.Abs("testdata")
	var procs []*exec.Cmd
	cleanup := func() {
		for _, p := range procs {
			p.Process.Kill()
			p.Wait()
		}
		os.RemoveAll(dir)
	}
	start := func(bin string, args ...string) error {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
		cmd.Dir = dir
		if err := cmd.Start(); err != nil {
			return err
		}
		procs = append(procs, cmd)
		return nil
	}
	writeConfig := func(name, listen, mgmt string, eab bool) (string, error) {
		pc := map[string]any{
			"listenAddress":           listen,
			"managementListenAddress": mgmt,
			"certificate":             filepath.Join(td, "pebble-localhost.pem"),
			"privateKey":              filepath.Join(td, "pebble-localhost.key"),
			"httpPort":                5002,
			"tlsPort":                 5001,
			"profiles": map[string]any{
				"default":    map[string]any{"description": "default", "validityPeriod": 90 * 24 * 3600},
				"shortlived": map[string]any{"description": "short", "validityPeriod": int(shortLived.Seconds())},
			},
		}
		if eab {
			pc["externalAccountBindingRequired"] = true
			pc["externalAccountMACKeys"] = map[string]string{eabKeyID: eabHMAC}
		}
		b, _ := json.Marshal(map[string]any{"pebble": pc})
		path := filepath.Join(dir, name)
		return path, os.WriteFile(path, b, 0o600)
	}

	if err := start(chall, "-dnsserver", dnsAddr, "-management", challMgmt,
		"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""); err != nil {
		cleanup()
		return nil, nil, err
	}
	plain, err := writeConfig("plain.json", "127.0.0.1:14000", "127.0.0.1:15000", false)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	withEAB, err := writeConfig("eab.json", "127.0.0.1:14001", "127.0.0.1:15001", true)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	for _, cfg := range []string{plain, withEAB} {
		if err := start(pebble, "-config", cfg, "-dnsserver", dnsAddr); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	for _, addr := range []string{challMgmt, "127.0.0.1:14000", "127.0.0.1:14001"} {
		if err := waitListening(addr); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	roots, err := os.ReadFile(filepath.Join(td, "pebble-minica.pem"))
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return &pebbleEnv{
		plainURL: "https://127.0.0.1:14000/dir",
		eabURL:   "https://127.0.0.1:14001/dir",
		roots:    string(roots),
	}, cleanup, nil
}

func waitListening(addr string) error {
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s did not start listening", addr)
}

// challDNS is a DNSSolver that writes TXT records into pebble-challtestsrv.
type challDNS struct{ presented int }

func (c *challDNS) Meta() plugin.Meta {
	return plugin.Meta{Name: "challtestsrv", Kind: plugin.KindDNS}
}
func (c *challDNS) Configure(context.Context, json.RawMessage) error { return nil }

func (c *challDNS) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	c.presented++
	return challPost("/set-txt", map[string]string{"host": info.EffectiveFQDN, "value": info.Value})
}

func (c *challDNS) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return challPost("/clear-txt", map[string]string{"host": info.EffectiveFQDN})
}

func challPost(path string, body any) error {
	b, _ := json.Marshal(body)
	resp, err := http.Post("http://"+challMgmt+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("challtestsrv %s: %s", path, resp.Status)
	}
	return nil
}

func requirePebble(t *testing.T) {
	t.Helper()
	if env == nil {
		t.Skip("pebble not available")
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
		CACertificates: env.roots,
		DNSResolvers:   []string{dnsAddr},
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
	iss := newIssuer(t, env.plainURL, nil, "default")
	dns := &challDNS{}

	cert, err := iss.Issue(ctx, plugin.IssueRequest{CSR: csrFor(t, "www.example.com", "*.example.com")}, plugin.ChallengeSolvers{DNS: dns})
	if err != nil {
		t.Fatal(err)
	}
	if dns.presented != 2 {
		t.Errorf("presented %d DNS challenges, want 2", dns.presented)
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
	iss := newIssuer(t, env.plainURL, nil, "shortlived")
	cert, err := iss.Issue(context.Background(), plugin.IssueRequest{CSR: csrFor(t, "short.example.com")}, plugin.ChallengeSolvers{DNS: &challDNS{}})
	if err != nil {
		t.Fatal(err)
	}
	if life := cert.NotAfter.Sub(cert.NotBefore); life > shortLived+time.Minute {
		t.Fatalf("lifetime %s, want about %s from the shortlived profile", life, shortLived)
	}
}

func TestExternalAccountBinding(t *testing.T) {
	requirePebble(t)
	ctx := context.Background()
	req := plugin.IssueRequest{CSR: csrFor(t, "eab.example.com")}
	solvers := plugin.ChallengeSolvers{DNS: &challDNS{}}

	if _, err := newIssuer(t, env.eabURL, nil, "").Issue(ctx, req, solvers); err == nil {
		t.Fatal("CA requiring EAB accepted an account without it")
	}
	bad := newIssuer(t, env.eabURL, &EAB{KeyID: eabKeyID, HMACKey: "d3JvbmcgaG1hYyBrZXkgd3JvbmcgaG1hYyBrZXk"}, "")
	if _, err := bad.Issue(ctx, req, solvers); err == nil {
		t.Fatal("wrong EAB HMAC accepted")
	}
	good := newIssuer(t, env.eabURL, &EAB{KeyID: eabKeyID, HMACKey: eabHMAC}, "")
	if _, err := good.Issue(ctx, req, solvers); err != nil {
		t.Fatalf("issue with EAB: %v", err)
	}
}

func TestAccountReuse(t *testing.T) {
	requirePebble(t)
	ctx := context.Background()
	a := newIssuer(t, env.plainURL, nil, "")
	if _, err := a.client(); err != nil {
		t.Fatal(err)
	}
	// A second instance with the same key finds the same account.
	b := &Issuer{}
	cfg, _ := json.Marshal(Config{DirectoryURL: env.plainURL, AccountKey: string(mustPEM(t, a)), AgreeToTerms: true, CACertificates: env.roots})
	if err := b.Configure(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := b.client(); err != nil {
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
