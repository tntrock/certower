// Package agentca is the private CA that authenticates agents and the
// agent API.
//
// Agents get client certificates from it at enrollment. The agent API's
// TLS certificate also comes from it, and agents pin the CA's fingerprint
// when they enroll, so they trust the server without any public CA and
// without depending on hostnames.
package agentca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
)

const keyName = "agent-ca"

// ClientLifetime is how long an agent's client certificate is valid.
// Agents renew it when a third of the lifetime remains. Tests shorten it.
var ClientLifetime = 90 * 24 * time.Hour

const serverLifetime = 7 * 24 * time.Hour

// CA signs agent and agent-API certificates.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer

	mu         sync.Mutex
	serverCert *tls.Certificate
}

// Load returns the instance's agent CA, creating it on first use.
func Load(ctx context.Context, st *store.Store, kek secrets.KEK) (*CA, error) {
	k, err := st.GetServerKey(ctx, keyName)
	if errors.Is(err, store.ErrNotFound) {
		if err := create(ctx, st, kek); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		// On conflict another server created it first; use theirs.
		k, err = st.GetServerKey(ctx, keyName)
	}
	if err != nil {
		return nil, err
	}
	keyPEM, err := secrets.Open(kek, secrets.Sealed{KEKID: k.KEKID, WrappedDEK: k.WrappedDEK, Ciphertext: k.Ciphertext}, aad())
	if err != nil {
		return nil, fmt.Errorf("agentca: unseal key: %w", err)
	}
	key, err := certutil.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	chain, err := certutil.ParseChainPEM([]byte(k.CertPEM))
	if err != nil {
		return nil, err
	}
	return &CA{cert: chain[0], certPEM: []byte(k.CertPEM), key: key}, nil
}

func aad() []byte { return []byte("server_key:" + keyName) }

func create(ctx context.Context, st *store.Store, kek secrets.KEK) error {
	key, err := certutil.GenerateKey(policy.ECDSAP256)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Certower Agent CA", Organization: []string{"Certower"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(20 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	keyPEM, err := certutil.EncodeKeyPEM(key)
	if err != nil {
		return err
	}
	sealed, err := secrets.Seal(kek, keyPEM, aad())
	if err != nil {
		return err
	}
	return st.CreateServerKey(ctx, store.ServerKey{
		Name: keyName, CertPEM: string(certutil.EncodeChainPEM([][]byte{der})),
		KEKID: sealed.KEKID, WrappedDEK: sealed.WrappedDEK, Ciphertext: sealed.Ciphertext,
	})
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

// CertPEM is the CA certificate agents trust.
func (c *CA) CertPEM() []byte { return c.certPEM }

// Fingerprint is the hex SHA-256 of the CA certificate, which agents pin.
func (c *CA) Fingerprint() string { return certutil.Fingerprint(c.cert.Raw) }

// Pool contains just the CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// SignClient issues an agent's client certificate for a CSR. The subject
// is the agent ID; the CSR's own subject is ignored.
func (c *CA) SignClient(csr *x509.CertificateRequest, agentID string) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("agentca: CSR signature: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"Certower agent"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ClientLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
}

// ServerTLSConfig is the TLS configuration for the agent API listener.
// Client certificates are verified when presented; enrollment is the only
// request allowed without one.
func (c *CA) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      c.Pool(),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return c.serverCertificate() },
	}
}

// serverCertificate returns a short-lived server certificate, re-issued
// when less than two days remain.
func (c *CA) serverCertificate() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.serverCert != nil && time.Until(c.serverCert.Leaf.NotAfter) > 2*24*time.Hour {
		return c.serverCert, nil
	}
	key, err := certutil.GenerateKey(policy.ECDSAP256)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "Certower agent API"},
		// Agents verify the chain to the pinned CA, not the hostname, so
		// the server can be reached under any name or address.
		DNSNames:    []string{"certower-agent-api"},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(serverLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	c.serverCert = &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}
	return c.serverCert, nil
}

// CertFingerprint is the fingerprint the server records for an agent's
// client certificate.
func CertFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

// ParseCSRPEM decodes a PEM certificate request.
func ParseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("agentca: expected a PEM CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
