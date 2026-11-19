package discovery

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func serve(t *testing.T, ca testCA, names []string) (port int) {
	t.Helper()
	key := ca.key // reuse a key; only the certificate matters here
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestScan(t *testing.T) {
	ca := newCA(t, "Scan Test Root")
	port := serve(t, ca, []string{"www.example.com"})
	ctx := context.Background()

	// Unknown root: reachable but untrusted.
	s := &Scanner{}
	res, err := s.Scan(ctx, "127.0.0.1", port, "www.example.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !codes(res.Findings)[CodeUntrusted] || res.Chain[0].Subject.CommonName != "www.example.com" {
		t.Fatalf("findings = %+v", res.Findings)
	}

	// Trusted root, right name: clean.
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	s = &Scanner{Roots: roots}
	if res, err := s.Scan(ctx, "127.0.0.1", port, "www.example.com", Options{}); err != nil || len(res.Findings) != 0 {
		t.Fatalf("clean scan: %+v %v", res, err)
	}

	// Wrong name.
	res, _ = s.Scan(ctx, "127.0.0.1", port, "other.example.com", Options{})
	if !codes(res.Findings)[CodeHostnameMismatch] {
		t.Fatalf("hostname mismatch not found: %+v", res.Findings)
	}
}

func TestScanRefusesLinkLocal(t *testing.T) {
	s := &Scanner{Timeout: time.Second}
	for _, host := range []string{"169.254.169.254", "fe80::1", "0.0.0.0"} {
		if _, err := s.Scan(context.Background(), host, 80, "", Options{}); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: err = %v, want ErrBlockedAddress", host, err)
		}
	}
}

func TestScanUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	s := &Scanner{Timeout: 2 * time.Second}
	if _, err := s.Scan(context.Background(), "127.0.0.1", port, "", Options{}); err == nil {
		t.Fatal("scan of a closed port succeeded")
	}

}
