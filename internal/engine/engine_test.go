package engine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// fakeCA signs certificates locally and lets tests script failures and
// renewal windows.
type fakeCA struct {
	mu        sync.Mutex
	key       crypto.Signer
	cert      *x509.Certificate
	serial    int64
	failNext  int           // fail this many Issue calls
	rejectAll bool          // refuse every request permanently
	lifetime  time.Duration // of issued certs
	window    func(notBefore, notAfter time.Time) *plugin.RenewalWindow
	replaces  []string
	revoked   map[string]int
	presented int
}

func newFakeCA(t *testing.T) *fakeCA {
	key, _ := certutil.GenerateKey(policy.ECDSAP256)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{9, 9, 9, 9},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &fakeCA{key: key, cert: cert, serial: 100, lifetime: 90 * 24 * time.Hour, revoked: map[string]int{}}
}

type fakeIssuer struct{ ca *fakeCA }

func (f *fakeIssuer) Meta() plugin.Meta {
	return plugin.Meta{Name: "fake-ca", Kind: plugin.KindIssuer, ConfigSchema: json.RawMessage(`{"type":"object"}`)}
}
func (f *fakeIssuer) Configure(context.Context, json.RawMessage) error { return nil }

func (f *fakeIssuer) Issue(_ context.Context, req plugin.IssueRequest, s plugin.ChallengeSolvers) (*plugin.IssuedCertificate, error) {
	ca := f.ca
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if s.DNS != nil {
		ca.presented++
	}
	if ca.rejectAll {
		return nil, fmt.Errorf("%w: name forbidden", plugin.ErrRejected)
	}
	if ca.failNext > 0 {
		ca.failNext--
		return nil, errors.New("CA unavailable")
	}
	ca.replaces = append(ca.replaces, req.Replaces)
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, err
	}
	ca.serial++
	nb := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial), Subject: csr.Subject, DNSNames: csr.DNSNames,
		NotBefore: nb, NotAfter: nb.Add(ca.lifetime)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	out := &plugin.IssuedCertificate{Chain: [][]byte{der, ca.cert.Raw}, NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}
	if ca.window != nil {
		out.Renewal = ca.window(tmpl.NotBefore, tmpl.NotAfter)
	}
	return out, nil
}

func (f *fakeIssuer) Revoke(_ context.Context, cert []byte, reason int) error {
	f.ca.mu.Lock()
	defer f.ca.mu.Unlock()
	f.ca.revoked[certutil.Fingerprint(cert)] = reason
	return nil
}

func (f *fakeIssuer) RenewalInfo(_ context.Context, cert []byte) (*plugin.RenewalWindow, error) {
	f.ca.mu.Lock()
	defer f.ca.mu.Unlock()
	if f.ca.window == nil {
		return nil, plugin.ErrNotSupported
	}
	leaf, _ := x509.ParseCertificate(cert)
	return f.ca.window(leaf.NotBefore, leaf.NotAfter), nil
}

type fakeDNS struct{}

func (fakeDNS) Meta() plugin.Meta                                { return plugin.Meta{Name: "fake-dns", Kind: plugin.KindDNS} }
func (fakeDNS) Configure(context.Context, json.RawMessage) error { return nil }
func (fakeDNS) Present(string, string, string) error             { return nil }
func (fakeDNS) CleanUp(string, string, string) error             { return nil }

type testEnv struct {
	e    *Engine
	ca   *fakeCA
	st   *store.Store
	org  *store.Organization
	proj *store.Project
	iss  *store.PluginConfig
	dns  *store.PluginConfig
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite:"+filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ca := newFakeCA(t)
	reg := plugin.NewRegistry()
	reg.Register(func() plugin.Plugin { return &fakeIssuer{ca: ca} })
	reg.Register(func() plugin.Plugin { return fakeDNS{} })
	kek, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{3}, 32))
	vault := &secrets.Vault{Store: st, KEK: kek}
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: reg}

	org, _ := st.CreateOrganization(ctx, "acme", "ACME")
	proj, _ := st.CreateProject(ctx, org.ID, "shop", "Shop")
	iss, err := configs.Create(ctx, pluginconfig.CreateRequest{OrgID: org.ID, Kind: plugin.KindIssuer, Plugin: "fake-ca", Name: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := configs.Create(ctx, pluginconfig.CreateRequest{OrgID: org.ID, Kind: plugin.KindDNS, Plugin: "fake-dns", Name: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: st, Vault: vault, Configs: configs, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// Retries become due immediately: the store compares with the real
		// clock, the engine schedules from this one.
		Now: func() time.Time { return time.Now().Add(-24 * time.Hour) }}
	return &testEnv{e: e, ca: ca, st: st, org: org, proj: proj, iss: iss, dns: dns}
}

func (te *testEnv) cert(t *testing.T, names ...string) *store.Certificate {
	t.Helper()
	c, err := te.st.CreateCertificate(context.Background(), store.Certificate{ProjectID: te.proj.ID, Name: names[0], Names: names,
		KeyType: string(policy.ECDSAP256), IssuerConfigID: te.iss.ID, DNSConfigID: te.dns.ID, KeyLocation: "server"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// drain runs jobs until none is runnable.
func (te *testEnv) drain(t *testing.T) int {
	t.Helper()
	n := 0
	for {
		ran, err := te.e.RunOne(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ran {
			return n
		}
		n++
		if n > 20 {
			t.Fatal("jobs never drain")
		}
	}
}

func TestIssueStoresVersionAndKey(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.ca.window = func(nb, na time.Time) *plugin.RenewalWindow {
		return &plugin.RenewalWindow{Start: na.Add(-30 * 24 * time.Hour), End: na.Add(-28 * 24 * time.Hour)}
	}
	c := te.cert(t, "www.example.com", "example.com")

	j1, err := te.e.RequestIssue(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	j2, _ := te.e.RequestIssue(ctx, c)
	if j1.ID != j2.ID {
		t.Fatal("second request queued a second job")
	}
	if n := te.drain(t); n != 1 {
		t.Fatalf("ran %d jobs, want 1", n)
	}

	got, _ := te.st.GetCertificate(ctx, c.ID)
	if got.Status != store.CertActive || got.LastError != "" {
		t.Fatalf("certificate = %+v", got)
	}
	v, err := te.st.CurrentVersion(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.ARICertID == "" || te.ca.presented != 1 {
		t.Errorf("ARI id %q, DNS presented %d", v.ARICertID, te.ca.presented)
	}
	if v.RenewAfter.Before(v.NotAfter.Add(-30*24*time.Hour)) || !v.RenewAfter.Before(v.NotAfter.Add(-28*24*time.Hour)) {
		t.Errorf("renew_after %s outside the ARI window", v.RenewAfter)
	}

	// The stored key matches the certificate and is encrypted at rest.
	row, _ := te.st.GetSecret(ctx, v.KeySecretID)
	if bytes.Contains(row.Ciphertext, []byte("PRIVATE KEY")) {
		t.Fatal("private key stored in plain text")
	}
	keyPEM, err := te.e.Vault.Get(ctx, v.KeySecretID)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := certutil.ParseKeyPEM(keyPEM)
	chain, _ := certutil.ParseChainPEM([]byte(v.ChainPEM))
	if !chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
		t.Fatal("stored key does not match certificate")
	}

	entries, _ := te.st.ListAudit(ctx, store.AuditQuery{OrgID: te.org.ID})
	if len(entries) == 0 || entries[0].Action != "cert.issued" {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestScheduledRenewalReplacesOldCert(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)
	first, _ := te.st.CurrentVersion(ctx, c.ID)

	// Not due yet: nothing is scheduled.
	te.e.Now = time.Now
	te.e.Schedule(ctx)
	if n := te.drain(t); n != 0 {
		t.Fatalf("renewed %d times before due", n)
	}

	// With no ARI, renewal is due when a third of the lifetime remains.
	te.e.Now = func() time.Time { return first.RenewAfter.Add(time.Minute) }
	if err := te.e.Schedule(ctx); err != nil {
		t.Fatal(err)
	}
	if n := te.drain(t); n != 1 {
		t.Fatalf("ran %d jobs, want 1 renewal", n)
	}
	second, _ := te.st.CurrentVersion(ctx, c.ID)
	if second.ID == first.ID {
		t.Fatal("no new version")
	}
	if last := te.ca.replaces[len(te.ca.replaces)-1]; last != first.ARICertID {
		t.Fatalf("renewal sent replaces=%q, want %q", last, first.ARICertID)
	}
	if !second.RenewAfter.Equal(RenewAt(second.NotBefore, second.NotAfter, nil, 1.0/3)) {
		t.Errorf("renew_after = %s", second.RenewAfter)
	}
}

func TestTransientFailureRetries(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.ca.failNext = 2
	c := te.cert(t, "www.example.com")
	j, _ := te.e.RequestIssue(ctx, c)

	te.e.RunOne(ctx)
	got, _ := te.st.GetCertificate(ctx, c.ID)
	job, _ := te.st.GetJob(ctx, j.ID)
	if got.Status != store.CertFailing || got.LastError == "" || job.Status != store.JobQueued || job.Attempts != 1 {
		t.Fatalf("after failure: cert %+v, job %+v", got, job)
	}
	te.drain(t)
	got, _ = te.st.GetCertificate(ctx, c.ID)
	job, _ = te.st.GetJob(ctx, j.ID)
	if got.Status != store.CertActive || job.Status != store.JobDone || job.Attempts != 3 {
		t.Fatalf("after recovery: cert %+v, job %+v", got, job)
	}
}

func TestPolicyViolationIsPermanent(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	c := te.cert(t, "evil.example.org")
	// Policy tightened after the certificate was created.
	te.st.PutPolicy(ctx, te.proj.ID, policy.Policy{AllowedNames: []string{"*.example.com"}})
	j, _ := te.e.RequestIssue(ctx, c)
	te.drain(t)

	got, _ := te.st.GetCertificate(ctx, c.ID)
	job, _ := te.st.GetJob(ctx, j.ID)
	if got.Status != store.CertInvalid || job.Status != store.JobFailed || job.Attempts != 1 {
		t.Fatalf("cert %+v, job %+v", got, job)
	}
	te.e.Schedule(ctx)
	if n := te.drain(t); n != 0 {
		t.Fatal("invalid certificate was rescheduled")
	}
}

func TestARIWindowMovedEarlier(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.ca.window = func(nb, na time.Time) *plugin.RenewalWindow {
		return &plugin.RenewalWindow{Start: na.Add(-30 * 24 * time.Hour), End: na.Add(-29 * 24 * time.Hour)}
	}
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)

	// The CA announces an incident: renew now.
	te.ca.window = func(nb, na time.Time) *plugin.RenewalWindow {
		return &plugin.RenewalWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(-time.Minute)}
	}
	te.e.Now = time.Now
	if err := te.e.Schedule(ctx); err != nil { // refreshes ARI
		t.Fatal(err)
	}
	v, _ := te.st.CurrentVersion(ctx, c.ID)
	if v.RenewAfter.After(time.Now()) || v.ARICheckedAt == nil {
		t.Fatalf("renew_after = %s, checked %v", v.RenewAfter, v.ARICheckedAt)
	}
	te.e.Schedule(ctx) // now due
	if n := te.drain(t); n != 1 {
		t.Fatalf("ran %d jobs, want 1 early renewal", n)
	}
}

func TestRevokeThenReplace(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)
	v, _ := te.st.CurrentVersion(ctx, c.ID)

	if err := te.e.Revoke(ctx, c, v, 1 /* keyCompromise */); err != nil {
		t.Fatal(err)
	}
	if te.ca.revoked[v.Fingerprint] != 1 {
		t.Fatal("CA was not asked to revoke")
	}
	again, _ := te.st.GetVersion(ctx, c.ID, v.ID)
	if err := te.e.Revoke(ctx, c, again, 1); err == nil {
		t.Fatal("revoked twice")
	}
	te.e.Now = time.Now
	te.e.Schedule(ctx)
	if n := te.drain(t); n != 1 {
		t.Fatalf("ran %d jobs, want 1 replacement", n)
	}
	if cur, err := te.st.CurrentVersion(ctx, c.ID); err != nil || cur.ID == v.ID {
		t.Fatalf("no replacement: %v %v", cur, err)
	}
}

func TestBackoff(t *testing.T) {
	for attempt, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 5: 16 * time.Minute, 9: 256 * time.Minute, 30: 6 * time.Hour} {
		got := Backoff(attempt)
		if got < want || got > want+want/5 {
			t.Errorf("Backoff(%d) = %s, want %s..%s", attempt, got, want, want+want/5)
		}
	}
}

func TestCARejectionIsPermanent(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.ca.rejectAll = true
	c := te.cert(t, "www.example.com")
	j, _ := te.e.RequestIssue(ctx, c)
	te.drain(t)
	got, _ := te.st.GetCertificate(ctx, c.ID)
	job, _ := te.st.GetJob(ctx, j.ID)
	if got.Status != store.CertInvalid || job.Status != store.JobFailed || job.Attempts != 1 {
		t.Fatalf("cert %+v, job %+v", got, job)
	}
}
