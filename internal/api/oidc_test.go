package api

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/tntrock/certower/internal/testutil/oidcmock"
)

func newMockIdP(t *testing.T) *oidcmock.Provider {
	p, err := oidcmock.New("certower-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// ssoLogin runs the browser flow and returns the session token, or the
// sso_error code the login page would show.
func (e *env) ssoLogin() (token, ssoError string) {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(e.srv.URL + "/api/v1/auth/oidc/login")
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	if code := resp.Request.URL.Query().Get("sso_error"); code != "" {
		return "", code
	}
	u, _ := url.Parse(e.srv.URL)
	for _, ck := range jar.Cookies(u) {
		if ck.Name == SessionCookie {
			return ck.Value, ""
		}
	}
	e.t.Fatalf("no session cookie; ended at %s", resp.Request.URL)
	return "", ""
}

func TestOIDCLogin(t *testing.T) {
	idp := newMockIdP(t)
	cfg := &OIDCConfig{Issuer: idp.URL, ClientID: "certower-test", ClientSecret: "s3cret", Name: "Example SSO"}
	e := newEnvWith(t, func(d *Deps) { d.OIDC = cfg })
	cfg.RedirectURL = e.srv.URL + "/api/v1/auth/oidc/callback"
	ctx := context.Background()

	var prov authProviders
	e.do("", "GET", "/api/v1/auth/providers", nil, 200, &prov)
	if prov.OIDC == nil || prov.OIDC.Name != "Example SSO" {
		t.Fatalf("providers = %+v", prov)
	}

	// No account and no auto-create.
	idp.SignInAs(map[string]any{"sub": "u1", "email": "ops@example.com", "email_verified": true})
	if _, code := e.ssoLogin(); code != "sso_no_account" {
		t.Fatalf("unknown user: %q", code)
	}

	// An existing account is linked by verified email, and group bindings
	// from the token apply.
	admin := e.user("admin@example.com", true)
	e.do(admin, "POST", "/api/v1/orgs", map[string]string{"slug": "acme", "name": "ACME"}, 201, nil)
	e.do(admin, "POST", "/api/v1/orgs/acme/bindings", createBindingRequest{Role: "viewer", OIDCGroup: "sre"}, 201, nil)
	hash := "$argon2id$v=19$m=65536,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
	ops, err := e.st.CreateUser(ctx, "ops@example.com", "Ops", hash, false)
	if err != nil {
		t.Fatal(err)
	}
	idp.SignInAs(map[string]any{"sub": "u1", "email": "OPS@example.com", "email_verified": "true", "groups": []string{"sre", "other"}})
	tok, code := e.ssoLogin()
	if code != "" {
		t.Fatalf("link: %q", code)
	}
	var me meResponse
	e.do(tok, "GET", "/api/v1/me", nil, 200, &me)
	if me.User.ID != ops.ID || len(me.Bindings) != 1 || me.Bindings[0].OIDCGroup != "sre" {
		t.Fatalf("me = %+v", me)
	}
	e.do(tok, "GET", "/api/v1/orgs/acme", nil, 200, nil)
	if got, err := e.st.GetUserByOIDC(ctx, idp.URL, "u1"); err != nil || got.ID != ops.ID {
		t.Fatalf("not linked: %v %v", got, err)
	}

	// The link follows the subject even if the email changes.
	idp.SignInAs(map[string]any{"sub": "u1", "email": "renamed@example.com", "email_verified": true})
	if tok, _ := e.ssoLogin(); tok == "" {
		t.Fatal("linked subject refused after email change")
	}

	// Another identity with the same email cannot take the account over.
	idp.SignInAs(map[string]any{"sub": "intruder", "email": "ops@example.com", "email_verified": true})
	if _, code := e.ssoLogin(); code != "sso_conflict" {
		t.Fatalf("takeover: %q", code)
	}

	// Unverified email.
	idp.SignInAs(map[string]any{"sub": "u2", "email": "admin@example.com", "email_verified": false})
	if _, code := e.ssoLogin(); code != "sso_email_unverified" {
		t.Fatalf("unverified: %q", code)
	}

	// Auto-create, limited to allowed domains.
	cfg.AutoCreate, cfg.AllowedDomains = true, []string{"example.com"}
	idp.SignInAs(map[string]any{"sub": "u3", "email": "x@evil.test", "email_verified": true})
	if _, code := e.ssoLogin(); code != "sso_domain_not_allowed" {
		t.Fatalf("domain: %q", code)
	}
	idp.SignInAs(map[string]any{"sub": "u3", "email": "new@example.com", "email_verified": true, "name": "New Person"})
	tok, code = e.ssoLogin()
	if code != "" {
		t.Fatalf("auto-create: %q", code)
	}
	e.do(tok, "GET", "/api/v1/me", nil, 200, &me)
	if me.User.Email != "new@example.com" || me.User.DisplayName != "New Person" || me.User.IsSuperuser {
		t.Fatalf("created = %+v", me.User)
	}
	// SSO-only accounts have no password to guess.
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "new@example.com", Password: ""}, 401, nil)
}

func TestOIDCCallbackRejectsForgedState(t *testing.T) {
	idp := newMockIdP(t)
	cfg := &OIDCConfig{Issuer: idp.URL, ClientID: "certower-test"}
	e := newEnvWith(t, func(d *Deps) { d.OIDC = cfg })
	cfg.RedirectURL = e.srv.URL + "/api/v1/auth/oidc/callback"

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Without the flow cookie (a login CSRF attempt).
	resp, err := noRedirect.Get(e.srv.URL + "/api/v1/auth/oidc/callback?code=x&state=y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error=sso_expired") {
		t.Fatalf("Location = %q", loc)
	}
	// With a cookie for a different state.
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/auth/oidc/callback?code=x&state=y", nil)
	req.AddCookie(&http.Cookie{Name: oidcFlowCookie, Value: "other.n.v"})
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error=sso_expired") {
		t.Fatalf("Location = %q", loc)
	}

	// Without OIDC configured, the endpoints do not exist.
	plain := newEnv(t)
	var prov authProviders
	plain.do("", "GET", "/api/v1/auth/providers", nil, 200, &prov)
	if prov.OIDC != nil {
		t.Fatal("oidc advertised")
	}
	plain.do("", "GET", "/api/v1/auth/oidc/login", nil, 404, nil)
}
