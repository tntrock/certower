// Package discovery finds certificates in the wild and flags problems.
package discovery

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Severity of a finding.
type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Finding is one problem with a served certificate chain.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Finding codes.
const (
	CodeExpired         = "expired"
	CodeExpiringSoon    = "expiring_soon"
	CodeNotYetValid     = "not_yet_valid"
	CodeDistrustedRoot  = "distrusted_root"
	CodeWeakKey         = "weak_key"
	CodeSHA1Signature   = "sha1_signature"
	CodeValidityTooLong = "validity_too_long"
)

// Options tunes the checks.
type Options struct {
	Now time.Time
	// ExpiryWarning is how far ahead of NotAfter to warn. Default 14 days.
	ExpiryWarning time.Duration
}

// distrust describes a root that browsers stopped trusting for TLS
// certificates issued after a cutoff.
type distrust struct {
	rootCN string
	org    string
	after  time.Time
	note   string
}

// Chrome 139 stopped trusting TLS certificates chaining to these roots with
// an earliest SCT after 2025-07-31 23:59:59 UTC. We approximate the SCT time
// with NotBefore, which CAs set at issuance.
var distrusted = []distrust{
	{"ePKI Root Certification Authority", "Chunghwa Telecom", time.Date(2025, 7, 31, 23, 59, 59, 0, time.UTC), "Chrome 139+"},
	{"HiPKI Root CA - G1", "Chunghwa Telecom", time.Date(2025, 7, 31, 23, 59, 59, 0, time.UTC), "Chrome 139+"},
}

// maxValidity returns the CA/Browser Forum maximum TLS certificate lifetime
// for a certificate issued at t (ballot SC-081).
func maxValidity(t time.Time) time.Duration {
	day := 24 * time.Hour
	switch {
	case !t.Before(time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 47 * day
	case !t.Before(time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 100 * day
	case !t.Before(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 200 * day
	default:
		return 398 * day
	}
}

// Check runs all rules against a served chain, leaf first. The chain may or
// may not include the root, as servers send it either way.
func Check(chain []*x509.Certificate, opt Options) []Finding {
	if len(chain) == 0 {
		return nil
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.ExpiryWarning == 0 {
		opt.ExpiryWarning = 14 * 24 * time.Hour
	}
	leaf := chain[0]
	var fs []Finding

	switch {
	case opt.Now.After(leaf.NotAfter):
		fs = append(fs, Finding{CodeExpired, Critical, fmt.Sprintf("expired on %s", leaf.NotAfter.Format(time.DateOnly))})
	case opt.Now.Before(leaf.NotBefore):
		fs = append(fs, Finding{CodeNotYetValid, Critical, fmt.Sprintf("not valid until %s", leaf.NotBefore.Format(time.DateOnly))})
	case leaf.NotAfter.Sub(opt.Now) < opt.ExpiryWarning:
		days := int(leaf.NotAfter.Sub(opt.Now).Hours() / 24)
		fs = append(fs, Finding{CodeExpiringSoon, Warning, fmt.Sprintf("expires in %d days", days)})
	}

	if d, ok := distrustedBy(chain); ok && leaf.NotBefore.After(d.after) {
		fs = append(fs, Finding{CodeDistrustedRoot, Critical, fmt.Sprintf(
			"chains to %q (%s), which %s does not trust for certificates issued after %s",
			d.rootCN, d.org, d.note, d.after.Format(time.DateOnly))})
	}

	if msg := weakKey(leaf); msg != "" {
		fs = append(fs, Finding{CodeWeakKey, Warning, msg})
	}

	for _, c := range chain {
		if isSelfSigned(c) {
			// Root signatures are not checked by clients.
			continue
		}
		if c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			fs = append(fs, Finding{CodeSHA1Signature, Critical, fmt.Sprintf("%q is signed with SHA-1", c.Subject.CommonName)})
		}
	}

	if limit := maxValidity(leaf.NotBefore); leaf.NotAfter.Sub(leaf.NotBefore) > limit+24*time.Hour {
		// One day of slack: CAs count inclusive seconds differently.
		fs = append(fs, Finding{CodeValidityTooLong, Warning, fmt.Sprintf(
			"lifetime of %d days exceeds the %d-day CA/B Forum limit", int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24), int(limit.Hours()/24))})
	}
	return fs
}

func distrustedBy(chain []*x509.Certificate) (distrust, bool) {
	for _, c := range chain {
		for _, d := range distrusted {
			for _, name := range []string{c.Issuer.CommonName, c.Subject.CommonName} {
				if strings.EqualFold(name, d.rootCN) {
					return d, true
				}
			}
		}
	}
	return distrust{}, false
}

func weakKey(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Sprintf("RSA key is %d bits, minimum is 2048", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return fmt.Sprintf("ECDSA key is %d bits, minimum is 256", k.Curve.Params().BitSize)
		}
	}
	return ""
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}
