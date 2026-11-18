package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
)

type env struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	eng *engine.Engine
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite:"+filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	kek, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{5}, 32))
	vault := &secrets.Vault{Store: st, KEK: kek}
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: testRegistry(t)}
	eng := &engine.Engine{Store: st, Vault: vault, Configs: configs, Log: log}
	srv := httptest.NewServer(New(Deps{Store: st, Log: log, Engine: eng, Configs: configs, Vault: vault}).Handler())
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &env{t: t, srv: srv, st: st, eng: eng}
}

// user creates an account directly in the store and logs it in.
func (e *env) user(email string, superuser bool) string {
	e.t.Helper()
	hash, _ := auth.HashPassword("long enough password")
	if _, err := e.st.CreateUser(context.Background(), email, "", hash, superuser); err != nil {
		e.t.Fatal(err)
	}
	var resp loginResponse
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: email, Password: "long enough password"}, 200, &resp)
	return resp.Token
}

// do sends a request and checks the status. out may be nil.
func (e *env) do(token, method, path string, body any, wantStatus int, out any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		e.t.Fatalf("%s %s: status %d, want %d; body %s", method, path, resp.StatusCode, wantStatus, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: decode: %v; body %s", method, path, err, raw)
		}
	}
}

func TestLogin(t *testing.T) {
	e := newEnv(t)
	e.user("admin@example.com", true)
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "admin@example.com", Password: "wrong password!!"}, 401, nil)
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "nobody@example.com", Password: "long enough password"}, 401, nil)
	e.do("", "GET", "/api/v1/me", nil, 401, nil)
	e.do("cws_bogus", "GET", "/api/v1/me", nil, 401, nil)

	tok := e.user("ops@example.com", false)
	var me meResponse
	e.do(tok, "GET", "/api/v1/me", nil, 200, &me)
	if me.Type != "user" || me.User.Email != "ops@example.com" || me.User.PasswordHash != "" {
		t.Fatalf("me = %+v", me)
	}
	e.do(tok, "POST", "/api/v1/auth/logout", nil, 204, nil)
	e.do(tok, "GET", "/api/v1/me", nil, 401, nil)
}

func TestCookieAuthRequiresJSON(t *testing.T) {
	e := newEnv(t)
	tok := e.user("admin@example.com", true)
	cookie := &http.Cookie{Name: SessionCookie, Value: tok}

	// A form post riding on the cookie is refused.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/orgs", bytes.NewBufferString("slug=acme"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("form POST with cookie: status %d, want 403", resp.StatusCode)
	}

	req, _ = http.NewRequest("POST", e.srv.URL+"/api/v1/orgs", bytes.NewBufferString(`{"slug":"acme"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("JSON POST with cookie: status %d, want 201", resp.StatusCode)
	}
}

func TestTenantIsolationAndRoles(t *testing.T) {
	e := newEnv(t)
	root := e.user("root@example.com", true)
	orgAdmin := e.user("boss@example.com", false)
	projAdmin := e.user("lead@example.com", false)
	operator := e.user("ops@example.com", false)
	outsider := e.user("other@example.com", false)

	e.do(orgAdmin, "POST", "/api/v1/orgs", slugName{Slug: "acme"}, 403, nil)
	e.do(root, "POST", "/api/v1/orgs", slugName{Slug: "acme", Name: "ACME"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs", slugName{Slug: "Bad Slug"}, 400, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/bindings", createBindingRequest{Role: "org_admin", User: "boss@example.com"}, 201, nil)

	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "shop"}, 201, nil)
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "erp"}, 201, nil)
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "shop"}, 409, nil)
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "project_admin", User: "lead@example.com"}, 201, nil)
	e.do(projAdmin, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "operator", User: "ops@example.com"}, 201, nil)

	// Outsiders cannot even tell the organization exists.
	e.do(outsider, "GET", "/api/v1/orgs/acme", nil, 404, nil)
	e.do(outsider, "GET", "/api/v1/orgs/acme/projects/shop", nil, 404, nil)
	var orgs []store.Organization
	e.do(outsider, "GET", "/api/v1/orgs", nil, 200, &orgs)
	if len(orgs) != 0 {
		t.Fatalf("outsider sees orgs %v", orgs)
	}

	// The operator sees only their project.
	var projects []store.Project
	e.do(operator, "GET", "/api/v1/orgs/acme/projects", nil, 200, &projects)
	if len(projects) != 1 || projects[0].Slug != "shop" {
		t.Fatalf("operator sees projects %v", projects)
	}
	e.do(operator, "GET", "/api/v1/orgs/acme/projects/shop", nil, 200, nil)
	e.do(operator, "GET", "/api/v1/orgs/acme/projects/erp", nil, 404, nil)
	e.do(operator, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "viewer", User: "other@example.com"}, 403, nil)

	// Policy: readable by members, writable only at the org level.
	pol := map[string]any{"allowedNames": []string{"*.shop.example.com"}, "maxValidityDays": 90}
	e.do(operator, "GET", "/api/v1/orgs/acme/projects/shop/policy", nil, 200, nil)
	e.do(projAdmin, "PUT", "/api/v1/orgs/acme/projects/shop/policy", pol, 403, nil)
	e.do(orgAdmin, "PUT", "/api/v1/orgs/acme/projects/shop/policy", pol, 200, nil)
	e.do(orgAdmin, "PUT", "/api/v1/orgs/acme/projects/shop/policy", map[string]any{"bogus": 1}, 400, nil)

	// Project admins cannot grant more than they hold.
	e.do(projAdmin, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "org_admin", User: "other@example.com"}, 403, nil)
	e.do(projAdmin, "POST", "/api/v1/orgs/acme/bindings", createBindingRequest{Role: "viewer", User: "other@example.com"}, 403, nil)
	e.do(projAdmin, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "project_admin", OIDCGroup: "shop-leads"}, 201, nil)

	// A custom role carrying key.export cannot be granted by anyone who
	// lacks key.export, which no built-in role has.
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/roles", createRoleRequest{Name: "key_custodian", Permissions: []rbac.Permission{"key.export", "cert.read"}}, 201, nil)
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/roles", createRoleRequest{Name: "viewer", Permissions: []rbac.Permission{"cert.read"}}, 409, nil)
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/roles", createRoleRequest{Name: "x", Permissions: []rbac.Permission{"root.everything"}}, 400, nil)
	e.do(orgAdmin, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "key_custodian", User: "ops@example.com"}, 403, nil)

	// Audit log records who did what.
	var entries []store.AuditEntry
	e.do(orgAdmin, "GET", "/api/v1/orgs/acme/audit", nil, 200, &entries)
	if len(entries) < 5 || entries[0].Action != "role.create" {
		t.Fatalf("audit entries = %+v", entries)
	}
	e.do(operator, "GET", "/api/v1/orgs/acme/audit", nil, 403, nil)
	e.do(projAdmin, "GET", "/api/v1/orgs/acme/audit?project=shop", nil, 200, &entries)
	for _, en := range entries {
		if en.ProjectID == "" {
			t.Fatalf("project audit view leaked org-level entry %+v", en)
		}
	}
	e.do(projAdmin, "GET", "/api/v1/orgs/acme/audit?project=erp", nil, 404, nil)
}

func TestServiceAccountTokens(t *testing.T) {
	e := newEnv(t)
	root := e.user("root@example.com", true)
	e.do(root, "POST", "/api/v1/orgs", slugName{Slug: "acme"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "shop"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "erp"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects/shop/service-accounts", map[string]string{"name": "ci"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/bindings", createBindingRequest{Role: "operator", ServiceAccount: "ci"}, 400, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "operator", ServiceAccount: "ci"}, 201, nil)

	var tok createTokenResponse
	e.do(root, "POST", "/api/v1/orgs/acme/projects/shop/service-accounts/ci/tokens", createTokenRequest{ExpiresInDays: 30}, 201, &tok)
	if tok.ExpiresAt == nil || len(tok.Token) < 40 {
		t.Fatalf("token response = %+v", tok)
	}

	var me meResponse
	e.do(tok.Token, "GET", "/api/v1/me", nil, 200, &me)
	if me.Type != "service_account" || me.ServiceAccount.Name != "ci" {
		t.Fatalf("me = %+v", me)
	}
	e.do(tok.Token, "GET", "/api/v1/orgs/acme/projects/shop/policy", nil, 200, nil)
	e.do(tok.Token, "GET", "/api/v1/orgs/acme/projects/erp", nil, 404, nil)
	e.do(tok.Token, "POST", "/api/v1/orgs/acme/projects/shop/service-accounts/ci/tokens", createTokenRequest{}, 403, nil)

	e.do(root, "DELETE", "/api/v1/orgs/acme/projects/shop/service-accounts/ci", nil, 204, nil)
	e.do(tok.Token, "GET", "/api/v1/me", nil, 401, nil)
}

func TestDeleteBindingScope(t *testing.T) {
	e := newEnv(t)
	root := e.user("root@example.com", true)
	lead := e.user("lead@example.com", false)
	e.user("boss@example.com", false)
	e.do(root, "POST", "/api/v1/orgs", slugName{Slug: "acme"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "shop"}, 201, nil)

	var orgBinding store.RoleBinding
	e.do(root, "POST", "/api/v1/orgs/acme/bindings", createBindingRequest{Role: "org_admin", User: "boss@example.com"}, 201, &orgBinding)
	e.do(root, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "project_admin", User: "lead@example.com"}, 201, nil)

	// An org-level binding cannot be removed through a project route.
	e.do(lead, "DELETE", "/api/v1/orgs/acme/projects/shop/bindings/"+orgBinding.ID, nil, 404, nil)
	e.do(lead, "DELETE", "/api/v1/orgs/acme/bindings/"+orgBinding.ID, nil, 403, nil)
	e.do(root, "DELETE", "/api/v1/orgs/acme/bindings/"+orgBinding.ID, nil, 204, nil)
}
