// Package acme is the generic ACME issuer. It works with any RFC 8555 CA,
// including those requiring External Account Binding, and supports ACME
// profiles and ACME Renewal Information (RFC 9773).
package acme

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/tntrock/certower/internal/capresets"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/dnsresolver"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/version"
	"github.com/tntrock/certower/pkg/plugin"
)

func init() {
	plugin.Default.Register(func() plugin.Plugin { return &Issuer{} })
}

// Config configures one ACME account.
type Config struct {
	// Preset fills DirectoryURL from internal/capresets when DirectoryURL
	// is empty.
	Preset       string `json:"preset,omitempty"`
	DirectoryURL string `json:"directoryUrl,omitempty"`
	Email        string `json:"email,omitempty"`
	// AccountKey is the PEM private key of the ACME account. The server
	// generates it when the issuer is created (see GenerateAccountKey) and
	// stores it as a secret.
	AccountKey string `json:"accountKey"`
	// EAB is required by most commercial CAs.
	EAB *EAB `json:"eab,omitempty"`
	// AgreeToTerms must be true; it records that the operator accepted the
	// CA's subscriber agreement.
	AgreeToTerms bool `json:"agreeToTerms"`
	// Profile is the default ACME profile, e.g. "shortlived". A request's
	// own Profile overrides it.
	Profile string `json:"profile,omitempty"`
	// CACertificates are extra PEM roots to trust for the ACME server's
	// TLS, for private CAs such as step-ca.
	CACertificates string `json:"caCertificates,omitempty"`
}

// EAB holds External Account Binding credentials from the CA.
type EAB struct {
	KeyID   string `json:"keyId"`
	HMACKey string `json:"hmacKey"` // base64url, as given by the CA
}

const configSchema = `{
  "type": "object",
  "required": ["accountKey", "agreeToTerms"],
  "properties": {
    "preset": {"type": "string", "title": "CA preset"},
    "directoryUrl": {"type": "string", "format": "uri", "title": "ACME directory URL"},
    "email": {"type": "string", "format": "email", "title": "Contact email"},
    "accountKey": {"type": "string", "title": "Account key", "x-secret": true, "x-generated": true},
    "eab": {
      "type": "object",
      "title": "External Account Binding",
      "required": ["keyId", "hmacKey"],
      "properties": {
        "keyId": {"type": "string", "title": "Key ID"},
        "hmacKey": {"type": "string", "title": "HMAC key", "x-secret": true}
      }
    },
    "agreeToTerms": {"type": "boolean", "const": true, "title": "I agree to the CA's terms of service"},
    "profile": {"type": "string", "title": "Default ACME profile"},
    "caCertificates": {"type": "string", "title": "Extra trusted roots (PEM)"}
  }
}`

// Issuer is an ACME account at one CA.
type Issuer struct {
	cfg        Config
	key        crypto.Signer
	httpClient *http.Client

	mu  sync.Mutex
	reg *registration.Resource
}

func (i *Issuer) Meta() plugin.Meta {
	return plugin.Meta{
		Name:         "acme",
		Kind:         plugin.KindIssuer,
		Version:      version.Version,
		Description:  "Any ACME (RFC 8555) certificate authority, with External Account Binding, profiles and ARI.",
		RunsOn:       plugin.RunsOnServer,
		ConfigSchema: json.RawMessage(configSchema),
	}
}

// GenerateAccountKey returns a new PEM account key.
func GenerateAccountKey() (string, error) {
	k, err := certutil.GenerateKey(policy.ECDSAP256)
	if err != nil {
		return "", err
	}
	p, err := certutil.EncodeKeyPEM(k)
	return string(p), err
}

// PrepareConfig generates the account key when none is given.
func (i *Issuer) PrepareConfig(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}
	if k, _ := m["accountKey"].(string); k == "" {
		key, err := GenerateAccountKey()
		if err != nil {
			return nil, err
		}
		m["accountKey"] = key
	}
	return json.Marshal(m)
}

func (i *Issuer) Configure(ctx context.Context, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	if cfg.DirectoryURL == "" && cfg.Preset != "" {
		p, ok := capresets.Get(cfg.Preset)
		if !ok {
			return fmt.Errorf("acme: unknown preset %q", cfg.Preset)
		}
		cfg.DirectoryURL = p.DirectoryURL
		if p.RequiresEAB && cfg.EAB == nil {
			return fmt.Errorf("acme: %s requires External Account Binding", p.Name)
		}
	}
	if cfg.DirectoryURL == "" {
		return errors.New("acme: directoryUrl is required")
	}
	if !cfg.AgreeToTerms {
		return errors.New("acme: agreeToTerms must be true")
	}
	key, err := certutil.ParseKeyPEM([]byte(cfg.AccountKey))
	if err != nil {
		return fmt.Errorf("acme: account key: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if cfg.CACertificates != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertificates)) {
			return errors.New("acme: caCertificates contains no certificates")
		}
		client.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}

	i.cfg, i.key, i.httpClient, i.reg = cfg, key, client, nil
	return nil
}

// user adapts the account to lego's registration.User.
type user struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *registration.Resource { return u.reg }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

// client returns a lego client bound to the account. With register set, the
// account is registered (or found by key) on first use; ARI lookups are
// unauthenticated and skip that. A new client is made per call because lego
// clients hold per-request challenge configuration.
func (i *Issuer) client(register bool) (*lego.Client, error) {
	if i.key == nil {
		return nil, errors.New("acme: not configured")
	}
	i.mu.Lock()
	defer i.mu.Unlock()

	u := &user{email: i.cfg.Email, reg: i.reg, key: i.key}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = i.cfg.DirectoryURL
	cfg.HTTPClient = i.httpClient
	cfg.UserAgent = "certower/" + version.Version
	c, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("acme: directory %s: %w", i.cfg.DirectoryURL, err)
	}
	if i.reg != nil || !register {
		return c, nil
	}

	// Reuse the existing account for this key if there is one.
	reg, err := c.Registration.ResolveAccountByKey()
	if err != nil {
		if i.cfg.EAB != nil {
			reg, err = c.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  i.cfg.EAB.KeyID,
				HmacEncoded:          i.cfg.EAB.HMACKey,
			})
		} else {
			reg, err = c.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		}
		if err != nil {
			return nil, fmt.Errorf("acme: register account: %w", err)
		}
	}
	i.reg = reg
	u.reg = reg
	return c, nil
}

// Issue obtains a certificate for a CSR using DNS-01.
//
// lego is not context-aware; ctx is checked only before starting.
func (i *Issuer) Issue(ctx context.Context, req plugin.IssueRequest, solvers plugin.ChallengeSolvers) (*plugin.IssuedCertificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, fmt.Errorf("acme: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("acme: CSR signature: %w", err)
	}
	if solvers.DNS == nil {
		return nil, errors.New("acme: a DNS provider is required (only DNS-01 is supported)")
	}

	c, err := i.client(true)
	if err != nil {
		return nil, err
	}
	// Resolvers are process-wide; see internal/dnsresolver.
	if err := c.Challenge.SetDNS01Provider(solvers.DNS, dnsresolver.ChallengeOptions()...); err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}

	profile := req.Profile
	if profile == "" {
		profile = i.cfg.Profile
	}
	res, err := c.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:            csr,
		Bundle:         true,
		Profile:        profile,
		ReplacesCertID: req.Replaces,
	})
	if err != nil {
		if isRejection(err) {
			return nil, fmt.Errorf("%w: %v", plugin.ErrRejected, err)
		}
		return nil, fmt.Errorf("acme: obtain certificate: %w", err)
	}

	chain, err := certutil.ParseChainPEM(res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("acme: parse issued chain: %w", err)
	}
	out := &plugin.IssuedCertificate{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter}
	for _, cert := range chain {
		out.Chain = append(out.Chain, cert.Raw)
	}
	if w, err := renewalInfo(c, chain[0]); err == nil {
		out.Renewal = w
	}
	return out, nil
}

func (i *Issuer) Revoke(ctx context.Context, cert []byte, reason int) error {
	c, err := i.client(true)
	if err != nil {
		return err
	}
	r := uint(reason)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err := c.Certificate.RevokeWithReason(certPEM, &r); err != nil {
		return fmt.Errorf("acme: revoke: %w", err)
	}
	return nil
}

func (i *Issuer) RenewalInfo(ctx context.Context, cert []byte) (*plugin.RenewalWindow, error) {
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	c, err := i.client(false)
	if err != nil {
		return nil, err
	}
	return renewalInfo(c, leaf)
}

func renewalInfo(c *lego.Client, leaf *x509.Certificate) (*plugin.RenewalWindow, error) {
	ri, err := c.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if errors.Is(err, api.ErrNoARI) {
		return nil, plugin.ErrNotSupported
	} else if err != nil {
		return nil, fmt.Errorf("acme: renewal info: %w", err)
	}
	return &plugin.RenewalWindow{Start: ri.SuggestedWindow.Start, End: ri.SuggestedWindow.End}, nil
}

// ARICertID returns the RFC 9773 identifier of a certificate, for
// IssueRequest.Replaces.
func ARICertID(cert []byte) (string, error) {
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return "", err
	}
	return certutil.ARICertID(leaf)
}

// rejections are ACME problem types (RFC 8555 section 6.7, RFC 8657) that
// the same request will hit again.
var rejections = []string{
	"rejectedIdentifier", "unsupportedIdentifier", "badCSR", "caa",
	"externalAccountRequired", "badSignatureAlgorithm", "badPublicKey",
	"unsupportedContact", "invalidProfile",
}

func isRejection(err error) bool {
	var p *legoacme.ProblemDetails
	if !errors.As(err, &p) {
		return false
	}
	for _, r := range rejections {
		if p.Type == "urn:ietf:params:acme:error:"+r {
			return true
		}
	}
	return false
}
