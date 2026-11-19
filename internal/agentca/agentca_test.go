package agentca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tntrock/certower/internal/agentproto"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
)

func load(t *testing.T) (*CA, *store.Store, secrets.KEK) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite:"+filepath.Join(t.TempDir(), "ca.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.Migrate(ctx)
	kek, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{4}, 32))
	ca, err := Load(ctx, st, kek)
	if err != nil {
		t.Fatal(err)
	}
	return ca, st, kek
}

func TestLoadIsStable(t *testing.T) {
	ca, st, kek := load(t)
	again, err := Load(context.Background(), st, kek)
	if err != nil || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload changed the CA: %v", err)
	}
	other, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{5}, 32))
	if _, err := Load(context.Background(), st, other); err == nil {
		t.Fatal("CA unsealed with the wrong KEK")
	}
}

func clientCert(t *testing.T, ca *CA, id string) tls.Certificate {
	t.Helper()
	key, _ := certutil.GenerateKey(policy.ECDSAP256)
	der, _ := certutil.CreateCSR(key, []string{"ignored"})
	csr, _ := x509.ParseCertificateRequest(der)
	cert, err := ca.SignClient(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert)
	if leaf.Subject.CommonName != id {
		t.Fatalf("client CN = %q", leaf.Subject.CommonName)
	}
	return tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key, Leaf: leaf}
}

func TestMutualTLS(t *testing.T) {
	ca, _, _ := load(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			io.WriteString(w, "anonymous")
			return
		}
		io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	// StartTLS would add httptest's own certificate; wrap the listener
	// with the CA's configuration instead, as the server does.
	srv.Listener = tls.NewListener(srv.Listener, ca.ServerTLSConfig())
	srv.Start()
	defer srv.Close()
	url := "https://" + srv.Listener.Addr().String()

	get := func(cfg *tls.Config) (string, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := c.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}

	// Pinned CA, any hostname (httptest uses 127.0.0.1).
	cfg := agentproto.PinnedClientConfig(strings.ToUpper(ca.Fingerprint()))
	if body, err := get(cfg); err != nil || body != "anonymous" {
		t.Fatalf("anonymous: %q %v", body, err)
	}
	cfg.Certificates = []tls.Certificate{clientCert(t, ca, "agent-123")}
	if body, err := get(cfg); err != nil || body != "agent-123" {
		t.Fatalf("with client cert: %q %v", body, err)
	}

	// A wrong pin is refused.
	if _, err := get(agentproto.PinnedClientConfig(strings.Repeat("ab", 32))); err == nil {
		t.Fatal("wrong pin accepted")
	}
	// A client certificate from another CA is refused by the server.
	other, _, _ := load(t)
	bad := agentproto.PinnedClientConfig(ca.Fingerprint())
	bad.Certificates = []tls.Certificate{clientCert(t, other, "intruder")}
	if body, err := get(bad); err == nil && body == "intruder" {
		t.Fatal("foreign client certificate accepted")
	}
}
