// Package oidcmock is a minimal OpenID provider for tests. It signs in
// whatever identity it is told to, enforcing PKCE (S256) and echoing the
// nonce, so a client's full authorization code flow can be exercised.
package oidcmock

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Provider is a running mock identity provider.
type Provider struct {
	// URL is the issuer.
	URL      string
	ClientID string

	srv *httptest.Server
	key *rsa.PrivateKey

	mu     sync.Mutex
	claims map[string]any
	codes  map[string][2]string // code -> nonce, PKCE challenge
}

// New starts a provider that accepts the given client ID. Close it when done.
func New(clientID string) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	p := &Provider{ClientID: clientID, key: key, codes: map[string][2]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	p.URL = p.srv.URL
	return p, nil
}

// Close stops the provider.
func (p *Provider) Close() { p.srv.Close() }

// SignInAs sets the claims (sub, email, groups, ...) of the next sign-ins.
func (p *Provider) SignInAs(claims map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = claims
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func randomCode() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "unknown client or PKCE missing", http.StatusBadRequest)
		return
	}
	code := randomCode()
	p.mu.Lock()
	p.codes[code] = [2]string{q.Get("nonce"), q.Get("code_challenge")}
	p.mu.Unlock()
	http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.Form.Get("code")
	p.mu.Lock()
	c, ok := p.codes[code]
	delete(p.codes, code)
	claims := map[string]any{}
	for k, v := range p.claims {
		claims[k] = v
	}
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c[1] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	now := time.Now()
	claims["iss"], claims["aud"], claims["nonce"] = p.URL, p.ClientID, c[0]
	claims["iat"], claims["exp"] = now.Unix(), now.Add(5*time.Minute).Unix()
	idToken, err := p.sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"access_token": randomCode(), "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (p *Provider) sign(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}
