package certutil

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	legocert "github.com/go-acme/lego/v4/certificate"

	"github.com/tntrock/certower/internal/policy"
)

func TestKeysAndCSR(t *testing.T) {
	for _, kt := range []policy.KeyType{policy.ECDSAP256, policy.ECDSAP384, policy.RSA2048, policy.Ed25519} {
		key, err := GenerateKey(kt)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		pemKey, err := EncodeKeyPEM(key)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if _, err := ParseKeyPEM(pemKey); err != nil {
			t.Fatalf("%s: round trip: %v", kt, err)
		}
		der, err := CreateCSR(key, []string{"www.example.com", "example.com", "192.0.2.1"})
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("%s: bad CSR signature: %v", kt, err)
		}
		if csr.Subject.CommonName != "www.example.com" || len(csr.DNSNames) != 2 || len(csr.IPAddresses) != 1 {
			t.Fatalf("%s: CSR = %v %v %v", kt, csr.Subject.CommonName, csr.DNSNames, csr.IPAddresses)
		}
	}
	if _, err := GenerateKey("dsa-1024"); err == nil {
		t.Error("unsupported key type accepted")
	}
}

func TestARICertIDMatchesLego(t *testing.T) {
	caKey, _ := GenerateKey(policy.ECDSAP256)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1, 2, 3, 4},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Serials with the high bit set need a leading zero byte in DER.
	for _, serial := range []int64{1, 0x7f, 0x80, 0xff00, 1 << 40} {
		leafKey, _ := GenerateKey(policy.ECDSAP256)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafKey.Public(), caKey)
		leaf, _ := x509.ParseCertificate(der)
		got, err := ARICertID(leaf)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := legocert.MakeARICertID(leaf)
		if got != want {
			t.Errorf("serial %#x: got %s, want %s", serial, got, want)
		}
	}
}
