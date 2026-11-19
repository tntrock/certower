package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/store"
)

// OIDCConfig enables single sign-on through an OpenID Connect provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is <public URL>/api/v1/auth/oidc/callback, registered
	// with the provider.
	RedirectURL string
	// Name labels the sign-in button, e.g. "Google" or "Entra ID".
	Name   string
	Scopes []string // default openid, email, profile
	// GroupsClaim names the ID token claim listing the user's groups, which
	// role bindings on OIDC groups match. Default "groups".
	GroupsClaim string
	// AllowedDomains, if set, limits sign-in to these email domains.
	AllowedDomains []string
	// AutoCreate creates accounts on first sign-in. Without it, an
	// administrator must create the user (by email) first.
	AutoCreate bool
	// SkipEmailVerified accepts emails the provider does not mark verified.
	// Only for providers that omit the claim but do verify addresses.
	SkipEmailVerified bool
}

const (
	oidcFlowCookie = "certower_oidc"
	oidcFlowPath   = "/api/v1/auth/oidc"
)

// oidcClient lazily discovers the provider, so a provider that is down at
// startup does not stop the server.
type oidcClient struct {
	cfg *OIDCConfig

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func (c *oidcClient) init(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.oauth != nil {
		return c.oauth, c.verifier, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, c.cfg.Issuer)
	if err != nil {
		return nil, nil, err
	}
	scopes := c.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	c.oauth = &oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  c.cfg.RedirectURL,
		Scopes:       scopes,
	}
	c.verifier = p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID})
	return c.oauth, c.verifier, nil
}

type authProviders struct {
	Password bool          `json:"password"`
	OIDC     *oidcProvider `json:"oidc"`
}

type oidcProvider struct {
	Name     string `json:"name"`
	LoginURL string `json:"loginUrl"`
}

// providers tells the login page which sign-in methods exist.
func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	resp := authProviders{Password: true}
	if s.oidc != nil {
		name := s.oidc.cfg.Name
		if name == "" {
			name = "SSO"
		}
		resp.OIDC = &oidcProvider{Name: name, LoginURL: oidcFlowPath + "/login"}
	}
	writeJSON(w, http.StatusOK, resp)
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// oidcLogin starts the authorization code flow with PKCE. The state, nonce
// and code verifier ride in a short-lived cookie scoped to the callback.
func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "not_found", "single sign-on is not configured")
		return
	}
	cfg, _, err := s.oidc.init(r.Context())
	if err != nil {
		s.log.Error("OIDC discovery failed", "issuer", s.oidc.cfg.Issuer, "err", err)
		s.ssoFail(w, r, "sso_unavailable")
		return
	}
	state, nonce, verifier := randomString(), randomString(), oauth2.GenerateVerifier()
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    state + "." + nonce + "." + verifier,
		Path:     oidcFlowPath,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   s.SecureCookies,
		// Lax, because the provider sends the browser back with a
		// cross-site top-level GET.
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// ssoFail sends the browser back to the login page with an error code.
func (s *Server) ssoFail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/?sso_error="+url.QueryEscape(code), http.StatusFound)
}

type idClaims struct {
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"` // some providers send "true"
	Name          string `json:"name"`
}

func (c idClaims) verified() bool {
	switch v := c.EmailVerified.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// groupsClaim reads a list of strings, or a single string, from the claims.
func groupsClaim(claims map[string]any, name string) []string {
	var out []string
	switch v := claims[name].(type) {
	case string:
		out = append(out, v)
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "not_found", "single sign-on is not configured")
		return
	}
	c, err := r.Cookie(oidcFlowCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcFlowCookie, Value: "", Path: oidcFlowPath, MaxAge: -1, HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
	if err != nil {
		s.ssoFail(w, r, "sso_expired")
		return
	}
	parts := strings.Split(c.Value, ".")
	q := r.URL.Query()
	if len(parts) != 3 || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(q.Get("state"))) != 1 {
		s.ssoFail(w, r, "sso_expired")
		return
	}
	nonce, verifier := parts[1], parts[2]
	if e := q.Get("error"); e != "" {
		s.log.Warn("OIDC provider returned an error", "error", e, "description", q.Get("error_description"))
		s.ssoFail(w, r, "sso_failed")
		return
	}

	u, groups, code, err := s.oidcUser(r.Context(), q.Get("code"), nonce, verifier)
	if err != nil {
		s.log.Warn("SSO login refused", "reason", code, "err", err, "ip", s.clientIP(r))
		s.ssoFail(w, r, code)
		return
	}

	token, tokenHash := auth.NewToken(auth.SessionPrefix)
	expires := time.Now().Add(s.SessionTTL).UTC()
	if err := s.store.CreateSession(r.Context(), u.ID, tokenHash, expires, groups...); err != nil {
		s.log.Error("create session", "err", err)
		s.ssoFail(w, r, "sso_failed")
		return
	}
	s.log.Info("SSO login", "email", u.Email, "groups", len(groups), "ip", s.clientIP(r))
	s.setSessionCookie(w, token, expires)
	http.Redirect(w, r, "/", http.StatusFound)
}

// oidcUser redeems the code and maps the identity to an account. code is
// the error code shown to the user when err is set.
func (s *Server) oidcUser(ctx context.Context, authCode, nonce, pkce string) (u *store.User, groups []string, code string, err error) {
	cfg, verifier, err := s.oidc.init(ctx)
	if err != nil {
		return nil, nil, "sso_unavailable", err
	}
	tok, err := cfg.Exchange(ctx, authCode, oauth2.VerifierOption(pkce))
	if err != nil {
		return nil, nil, "sso_failed", fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, nil, "sso_failed", errors.New("no id_token in token response")
	}
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, nil, "sso_failed", fmt.Errorf("id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return nil, nil, "sso_failed", errors.New("id token nonce mismatch")
	}
	var claims idClaims
	var all map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, nil, "sso_failed", err
	}
	if err := idt.Claims(&all); err != nil {
		return nil, nil, "sso_failed", err
	}
	groupsName := s.oidc.cfg.GroupsClaim
	if groupsName == "" {
		groupsName = "groups"
	}
	groups = groupsClaim(all, groupsName)

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return nil, nil, "sso_no_email", errors.New("id token has no email claim; request the email scope")
	}
	if !claims.verified() && !s.oidc.cfg.SkipEmailVerified {
		return nil, nil, "sso_email_unverified", fmt.Errorf("email %s is not verified", email)
	}
	if d := s.oidc.cfg.AllowedDomains; len(d) > 0 {
		_, domain, _ := strings.Cut(email, "@")
		if !slices.Contains(d, domain) {
			return nil, nil, "sso_domain_not_allowed", fmt.Errorf("domain of %s not allowed", email)
		}
	}

	u, err = s.store.GetUserByOIDC(ctx, idt.Issuer, idt.Subject)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		u, err = s.store.GetUserByEmail(ctx, email)
		switch {
		case err == nil:
			// First SSO sign-in for an existing account: link it, unless it
			// already belongs to another identity.
			iss, sub, err := s.store.OIDCSubject(ctx, u.ID)
			if err != nil {
				return nil, nil, "sso_failed", err
			}
			if sub != "" && (iss != idt.Issuer || sub != idt.Subject) {
				return nil, nil, "sso_conflict", fmt.Errorf("account %s is linked to another identity", email)
			}
			if err := s.store.LinkOIDC(ctx, u.ID, idt.Issuer, idt.Subject); err != nil {
				return nil, nil, "sso_failed", err
			}
		case errors.Is(err, store.ErrNotFound):
			if !s.oidc.cfg.AutoCreate {
				return nil, nil, "sso_no_account", fmt.Errorf("no account for %s", email)
			}
			if u, err = s.store.CreateOIDCUser(ctx, email, claims.Name, idt.Issuer, idt.Subject); err != nil {
				return nil, nil, "sso_failed", err
			}
			s.log.Info("created account on first SSO sign-in", "email", email)
		default:
			return nil, nil, "sso_failed", err
		}
	default:
		return nil, nil, "sso_failed", err
	}
	if u.Disabled {
		return nil, nil, "sso_disabled", fmt.Errorf("account %s is disabled", email)
	}
	return u, groups, "", nil
}
