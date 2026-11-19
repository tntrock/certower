package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/agentca"
	"github.com/tntrock/certower/internal/api"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
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
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: reg}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := &engine.Engine{Store: st, Vault: vault, Configs: configs, Log: log, Poll: time.Second}
	agentCA, _ := agentca.Load(ctx, st, kek)
	apiH := api.New(api.Deps{Store: st, Log: log, Engine: eng, Configs: configs, Vault: vault, AgentCA: agentCA, AgentURL: "https://certower.example.com:8443"}).Handler()
	mux := http.NewServeMux()
	mux.Handle("/api/", apiH)
	mux.Handle("/", web.Handler())
	go eng.Run(ctx)

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

	inv, _ := st.CreateAgentInvitation(ctx, web1.ID, "web-01", []byte("demo-token"), time.Now().Add(24*time.Hour))
	_ = inv

	srv := &http.Server{Addr: addr, Handler: mux}
	t.Logf("demo server on http://%s (admin@example.com / demo password 123)", addr)
	if err := srv.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
}
