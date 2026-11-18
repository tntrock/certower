package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

var day = 24 * time.Hour

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, key}
}

func (ca testCA) leaf(t *testing.T, notBefore time.Time, lifetime time.Duration) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(lifetime),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func codes(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Code] = true
	}
	return m
}

func TestDistrustedChunghwa(t *testing.T) {
	cht := newCA(t, "HiPKI Root CA - G1")
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)

	before := cht.leaf(t, time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC), 397*day)
	if codes(Check([]*x509.Certificate{before}, Options{Now: now}))[CodeDistrustedRoot] {
		t.Error("certificate issued before cutoff flagged as distrusted")
	}

	after := cht.leaf(t, time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC), 397*day)
	if !codes(Check([]*x509.Certificate{after}, Options{Now: now}))[CodeDistrustedRoot] {
		t.Error("certificate issued after cutoff not flagged")
	}

	other := newCA(t, "Some Other Root")
	ok := other.leaf(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), 90*day)
	if fs := Check([]*x509.Certificate{ok}, Options{Now: now}); len(fs) != 0 {
		t.Errorf("healthy certificate has findings: %v", fs)
	}
}

func TestExpiry(t *testing.T) {
	ca := newCA(t, "Root")
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		notBefore time.Time
		lifetime  time.Duration
		want      string
	}{
		{now.Add(-100 * day), 90 * day, CodeExpired},
		{now.Add(-85 * day), 90 * day, CodeExpiringSoon},
		{now.Add(day), 90 * day, CodeNotYetValid},
	}
	for _, c := range cases {
		got := codes(Check([]*x509.Certificate{ca.leaf(t, c.notBefore, c.lifetime)}, Options{Now: now}))
		if !got[c.want] {
			t.Errorf("want %s, got %v", c.want, got)
		}
	}
}

func TestValidityTooLong(t *testing.T) {
	ca := newCA(t, "Root")
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	// Issued after 2026-03-15: limit is 200 days.
	long := ca.leaf(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), 397*day)
	if !codes(Check([]*x509.Certificate{long}, Options{Now: now}))[CodeValidityTooLong] {
		t.Error("397-day cert issued in 2026-06 not flagged")
	}
	fine := ca.leaf(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), 199*day)
	if codes(Check([]*x509.Certificate{fine}, Options{Now: now}))[CodeValidityTooLong] {
		t.Error("199-day cert flagged")
	}
}
