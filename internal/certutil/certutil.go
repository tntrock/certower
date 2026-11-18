// Package certutil generates keys and CSRs and converts certificate formats.
// The agent and the server share it.
package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"

	"github.com/tntrock/certower/internal/policy"
)

// GenerateKey creates a private key of the given type.
func GenerateKey(kt policy.KeyType) (crypto.Signer, error) {
	switch kt {
	case policy.ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case policy.ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case policy.RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case policy.RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case policy.RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case policy.Ed25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	return nil, fmt.Errorf("certutil: unsupported key type %q", kt)
}

// CreateCSR returns a DER CSR for the names. The first name becomes the
// subject CN; all names go into the SAN extension. IP addresses are put in
// IP SANs.
func CreateCSR(key crypto.Signer, names []string) ([]byte, error) {
	if len(names) == 0 {
		return nil, errors.New("certutil: at least one name is required")
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

// EncodeKeyPEM encodes a private key as PKCS#8 PEM.
func EncodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM decodes a PKCS#8, PKCS#1 or SEC1 PEM private key.
func ParseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("certutil: no PEM block found")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("certutil: unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("certutil: key cannot sign")
	}
	return s, nil
}

// EncodeChainPEM encodes DER certificates as concatenated PEM.
func EncodeChainPEM(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// ParseChainPEM decodes every CERTIFICATE block, in order.
func ParseChainPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("certutil: no certificates found")
	}
	return out, nil
}

// Fingerprint is the lowercase hex SHA-256 of a certificate's DER.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// ARICertID returns the RFC 9773 identifier of a certificate: the
// base64url Authority Key Identifier and DER serial number value, joined
// by a dot.
func ARICertID(leaf *x509.Certificate) (string, error) {
	if len(leaf.AuthorityKeyId) == 0 {
		return "", errors.New("certutil: certificate has no Authority Key Identifier")
	}
	der, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil {
		return "", err
	}
	// Serial numbers are at most 20 bytes, so the DER length is one byte:
	// skip the tag and length to keep the value.
	if len(der) < 3 || der[1]&0x80 != 0 {
		return "", errors.New("certutil: unexpected serial number encoding")
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." +
		base64.RawURLEncoding.EncodeToString(der[2:]), nil
}
