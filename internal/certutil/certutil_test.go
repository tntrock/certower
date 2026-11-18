package certutil

import (
	"crypto/x509"
	"testing"

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
