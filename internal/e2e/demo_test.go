package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/agentca"
	"github.com/tntrock/certower/internal/api"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/plugins/webhook"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/internal/testutil/oidcmock"
	"github.com/tntrock/certower/pkg/plugin"
	"github.com/tntrock/certower/web"
)

// flakyCA always fails, to show certificates being retried.
type flakyCA struct{ localIssuer }

func (f *flakyCA) Meta() plugin.Meta {
	m := f.localIssuer.Meta()
	m.Name = "flaky-ca"
	return m
}

func (f *flakyCA) Issue(context.Context, plugin.IssueRequest, plugin.ChallengeSolvers) (*plugin.IssuedCertificate, error) {
	return nil, errors.New("connection to CA timed out")
}

// TestDemoServer runs the API and web UI with sample data until
// interrupted, for UI development and screenshots:
//
//	CERTOWER_DEMO=127.0.0.1:18090 go test ./internal/e2e -run TestDemoServer -timeout 0
//
// Sign in as admin@example.com / "demo password 123".
func TestDemoServer(t *testing.T) {
	addr := os.Getenv("CERTOWER_DEMO")
	if addr == "" {
		t.Skip("set CERTOWER_DEMO=host:port to run the demo server")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite:"+filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Migrate(ctx)
	kek, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{1}, 32))
	vault := &secrets.Vault{Store: st, KEK: kek}
	ca := newLocalCA(t)
	reg := plugin.NewRegistry()
	reg.Register(func() plugin.Plugin { return &localIssuer{ca: ca} })
	reg.Register(func() plugin.Plugin { return &flakyCA{localIssuer{ca: ca}} })
	reg.Register(func() plugin.Plugin { return &webhook.Notifier{} })
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: reg}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	eng := &engine.Engine{Store: st, Vault: vault, Configs: configs, Log: log, Poll: time.Second}
	agentCA, _ := agentca.Load(ctx, st, kek)
	// A mock identity provider: "Sign in with Demo SSO" logs in dev@example.com
	// in the web-team group.
	idp, err := oidcmock.New("certower-demo")
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	idp.SignInAs(map[string]any{"sub": "dev-1", "email": "dev@example.com", "email_verified": true, "name": "Dev", "groups": []string{"web-team"}})
	oidcCfg := &api.OIDCConfig{Issuer: idp.URL, ClientID: "certower-demo", RedirectURL: "http://" + addr + "/api/v1/auth/oidc/callback", Name: "Demo SSO", AutoCreate: true}
	apiH := api.New(api.Deps{Store: st, Log: log, Engine: eng, Configs: configs, Vault: vault, AgentCA: agentCA, AgentURL: "https://certower.example.com:8443", OIDC: oidcCfg}).Handler()
	mux := http.NewServeMux()
	mux.Handle("/api/", apiH)
	mux.Handle("/", web.Handler())

	hash, _ := auth.HashPassword("demo password 123")
	admin, _ := st.CreateUser(ctx, "admin@example.com", "Admin", hash, true)
	org, _ := st.CreateOrganization(ctx, "acme", "ACME Corp")
	st.CreateRoleBinding(ctx, store.RoleBinding{OrgID: org.ID, Role: "org_admin", UserID: admin.ID})
	ops, _ := st.CreateUser(ctx, "ops@example.com", "Ops", hash, false)
	web1, _ := st.CreateProject(ctx, org.ID, "web", "Web services")
	st.CreateProject(ctx, org.ID, "erp", "Internal ERP")
	st.CreateRoleBinding(ctx, store.RoleBinding{OrgID: org.ID, ProjectID: web1.ID, Role: "operator", UserID: ops.ID})
	st.CreateRoleBinding(ctx, store.RoleBinding{OrgID: org.ID, ProjectID: web1.ID, Role: "viewer", OIDCGroup: "web-team"})

	local, err := configs.Create(ctx, pluginconfig.CreateRequest{OrgID: org.ID, Kind: plugin.KindIssuer, Plugin: "local-ca", Name: "corp-ca", Config: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	flaky, _ := configs.Create(ctx, pluginconfig.CreateRequest{OrgID: org.ID, Kind: plugin.KindIssuer, Plugin: "flaky-ca", Name: "partner-ca", Config: json.RawMessage(`{}`)})
	st.PutPolicy(ctx, web1.ID, policy.Policy{AllowedNames: []string{"*.example.com", "example.com"}, AllowWildcard: true})

	mk := func(name string, names []string, issuer *store.PluginConfig, loc string) *store.Certificate {
		c, err := st.CreateCertificate(ctx, store.Certificate{ProjectID: web1.ID, Name: name, Names: names, KeyType: "ecdsa-p256",
			IssuerConfigID: issuer.ID, KeyLocation: loc, OwnerEmail: "ops@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if loc == "server" {
			eng.RequestIssue(ctx, c)
		}
		return c
	}
	mk("www", []string{"www.example.com", "example.com"}, local, "server")
	mk("api", []string{"api.example.com"}, local, "server")
	mk("wildcard", []string{"*.example.com"}, local, "server")
	mk("partner-gateway", []string{"partner.example.com"}, flaky, "server")
	mk("shop-edge", []string{"shop.example.com"}, local, "agent")
	bad := mk("legacy", []string{"legacy.example.org"}, local, "server")
	_ = bad

	// Discovery: endpoints serving various certificates.
	serveDemo := func(caCN string, names []string, notBefore time.Time, life time.Duration) int {
		caKey, _ := certutil.GenerateKey(policy.ECDSAP256)
		caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: caCN}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: notBefore.Add(-time.Hour), NotAfter: notBefore.Add(10 * 365 * 24 * time.Hour)}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
		caCert, _ := x509.ParseCertificate(caDER)
		key, _ := certutil.GenerateKey(policy.ECDSAP256)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notBefore.Add(life)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
		ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}})
		go serveHandshakes(ln)
		return ln.Addr().(*net.TCPAddr).Port
	}
	now := time.Now()
	for _, d := range []struct {
		host      string
		caCN      string
		notBefore time.Time
		life      time.Duration
	}{
		{"gov-portal.example.tw", "HiPKI Root CA - G1", time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), 397 * 24 * time.Hour},
		{"old-intranet.example.com", "Old Internal CA", now.Add(-400 * 24 * time.Hour), 395 * 24 * time.Hour},
		{"status.example.com", "Example Issuing CA", now.Add(-30 * 24 * time.Hour), 90 * 24 * time.Hour},
	} {
		port := serveDemo(d.caCN, []string{d.host}, d.notBefore, d.life)
		st.CreateEndpoint(ctx, store.DiscoveryEndpoint{OrgID: org.ID, Host: "127.0.0.1", Port: port, SNI: d.host})
	}
	st.CreateEndpoint(ctx, store.DiscoveryEndpoint{OrgID: org.ID, ProjectID: web1.ID, Host: "127.0.0.1", Port: 1, SNI: "legacy-vpn.example.com"})
	configs.Create(ctx, pluginconfig.CreateRequest{OrgID: org.ID, Kind: plugin.KindNotifier, Plugin: "webhook", Name: "ops-slack",
		Config: json.RawMessage(`{"url":"https://hooks.example.invalid/demo","format":"slack","minSeverity":"warning"}`)})

	inv, _ := st.CreateAgentInvitation(ctx, web1.ID, "web-01", []byte("demo-token"), time.Now().Add(24*time.Hour))
	_ = inv

	go eng.Run(ctx) // after seeding, so the first pass sees everything
	srv := &http.Server{Addr: addr, Handler: mux}
	t.Logf("demo server on http://%s (admin@example.com / demo password 123)", addr)
	if err := srv.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
}
