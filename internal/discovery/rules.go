// Package discovery finds certificates in the wild and flags problems.
package discovery

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"
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
	// Params are the values in Message, so a UI can word it in another
	// language. Keys depend on Code.
	Params map[string]string `json:"params,omitempty"`
}

func finding(code string, sev Severity, params map[string]string, format string, args ...any) Finding {
	return Finding{Code: code, Severity: sev, Message: fmt.Sprintf(format, args...), Params: params}
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
		fs = append(fs, finding(CodeExpired, Critical, map[string]string{"date": leaf.NotAfter.Format(time.DateOnly)},
			"expired on %s", leaf.NotAfter.Format(time.DateOnly)))
	case opt.Now.Before(leaf.NotBefore):
		fs = append(fs, finding(CodeNotYetValid, Critical, map[string]string{"date": leaf.NotBefore.Format(time.DateOnly)},
			"not valid until %s", leaf.NotBefore.Format(time.DateOnly)))
	case leaf.NotAfter.Sub(opt.Now) < opt.ExpiryWarning:
		days := int(leaf.NotAfter.Sub(opt.Now).Hours() / 24)
		fs = append(fs, finding(CodeExpiringSoon, Warning, map[string]string{"days": strconv.Itoa(days)}, "expires in %d days", days))
	}

	if d, ok := distrustedBy(chain); ok && leaf.NotBefore.After(d.after) {
		fs = append(fs, finding(CodeDistrustedRoot, Critical,
			map[string]string{"root": d.rootCN, "owner": d.org, "by": d.note, "date": d.after.Format(time.DateOnly)},
			"chains to %q (%s), which %s does not trust for certificates issued after %s",
			d.rootCN, d.org, d.note, d.after.Format(time.DateOnly)))
	}

	if f, ok := weakKey(leaf); ok {
		fs = append(fs, f)
	}

	for _, c := range chain {
		if isSelfSigned(c) {
			// Root signatures are not checked by clients.
			continue
		}
		if c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			fs = append(fs, finding(CodeSHA1Signature, Critical, map[string]string{"name": c.Subject.CommonName}, "%q is signed with SHA-1", c.Subject.CommonName))
		}
	}

	if limit := maxValidity(leaf.NotBefore); leaf.NotAfter.Sub(leaf.NotBefore) > limit+24*time.Hour {
		// One day of slack: CAs count inclusive seconds differently.
		days, maxDays := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24), int(limit.Hours()/24)
		fs = append(fs, finding(CodeValidityTooLong, Warning, map[string]string{"days": strconv.Itoa(days), "max": strconv.Itoa(maxDays)},
			"lifetime of %d days exceeds the %d-day CA/B Forum limit", days, maxDays))
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

func weakKey(c *x509.Certificate) (Finding, bool) {
	var alg string
	var bits, min int
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		alg, bits, min = "RSA", k.N.BitLen(), 2048
	case *ecdsa.PublicKey:
		alg, bits, min = "ECDSA", k.Curve.Params().BitSize, 256
	default:
		return Finding{}, false
	}
	if bits >= min {
		return Finding{}, false
	}
	return finding(CodeWeakKey, Warning, map[string]string{"alg": alg, "bits": strconv.Itoa(bits), "min": strconv.Itoa(min)},
		"%s key is %d bits, minimum is %d", alg, bits, min), true
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}
