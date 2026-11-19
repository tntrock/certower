package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/agent"
	"github.com/tntrock/certower/internal/agentapi"
	"github.com/tntrock/certower/internal/agentca"
	"github.com/tntrock/certower/internal/api"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// localCA is an issuer plugin that signs with an in-memory CA, so the agent
// flow can be tested without an ACME server.
type localCA struct {
	cert *x509.Certificate
	key  any
}

var localSerial atomic.Int64

func newLocalCA(t *testing.T) *localCA {
	key, _ := certutil.GenerateKey(policy.ECDSAP256)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local Test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{7, 7, 7},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &localCA{cert: c, key: key}
}

type localIssuer struct{ ca *localCA }

func (l *localIssuer) Meta() plugin.Meta {
	return plugin.Meta{Name: "local-ca", Kind: plugin.KindIssuer, ConfigSchema: json.RawMessage(`{"type":"object"}`)}
}
func (l *localIssuer) Configure(context.Context, json.RawMessage) error { return nil }
func (l *localIssuer) Issue(_ context.Context, req plugin.IssueRequest, _ plugin.ChallengeSolvers) (*plugin.IssuedCertificate, error) {
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, err
	}
	nb := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(10 + localSerial.Add(1)), Subject: csr.Subject, DNSNames: csr.DNSNames,
		NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, l.ca.cert, csr.PublicKey, l.ca.key)
	if err != nil {
		return nil, err
	}
	return &plugin.IssuedCertificate{Chain: [][]byte{der, l.ca.cert.Raw}, NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}, nil
}
func (l *localIssuer) Revoke(context.Context, []byte, int) error { return nil }
func (l *localIssuer) RenewalInfo(context.Context, []byte) (*plugin.RenewalWindow, error) {
	return nil, plugin.ErrNotSupported
}

// fileTLSServer behaves like a web server that loads its certificate from
// disk: every handshake reads the files, so it serves whatever was last
// installed.
func fileTLSServer(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		return &c, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveHandshakes(ln)
	return ln.Addr().String()
}

// staticTLSServer always serves an unrelated certificate, like a web
// server that ignored the reload.
func staticTLSServer(t *testing.T) string {
	t.Helper()
	key, _ := certutil.GenerateKey(policy.ECDSAP256)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stale"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveHandshakes(ln)
	return ln.Addr().String()
}

func serveHandshakes(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			c.(*tls.Conn).Handshake()
			c.Close()
		}()
	}
}

type agentEnv struct {
	st       *store.Store
	eng      *engine.Engine
	api      *client
	agentURL string
}

func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite:"+filepath.Join(t.TempDir(), "agent-e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kek, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{6}, 32))
	vault := &secrets.Vault{Store: st, KEK: kek}
	ca := newLocalCA(t)
	reg := plugin.NewRegistry()
	reg.Register(func() plugin.Plugin { return &localIssuer{ca: ca} })
	configs := &pluginconfig.Service{Store: st, Vault: vault, Registry: reg}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := &engine.Engine{Store: st, Vault: vault, Configs: configs, Log: log}
	agentCA, err := agentca.Load(ctx, st, kek)
	if err != nil {
		t.Fatal(err)
	}

	agentSrv := httptest.NewUnstartedServer((&agentapi.Server{Store: st, CA: agentCA, Engine: eng, Log: log}).Handler())
	agentSrv.Listener = tls.NewListener(agentSrv.Listener, agentCA.ServerTLSConfig())
	agentSrv.Start()
	t.Cleanup(agentSrv.Close)
	agentURL := "https://" + agentSrv.Listener.Addr().String()

	apiSrv := httptest.NewServer(api.New(api.Deps{Store: st, Log: log, Engine: eng, Configs: configs, Vault: vault,
		AgentCA: agentCA, AgentURL: agentURL}).Handler())
	t.Cleanup(apiSrv.Close)

	hash, _ := auth.HashPassword("agent e2e password")
	st.CreateUser(ctx, "admin@example.com", "", hash, true)
	c := &client{t: t, base: apiSrv.URL + "/api/v1"}
	var login struct{ Token string }
	c.call("POST", "/auth/login", map[string]string{"email": "admin@example.com", "password": "agent e2e password"}, 200, &login)
	c.token = login.Token
	c.call("POST", "/orgs", map[string]string{"slug": "acme"}, 201, nil)
	c.call("POST", "/orgs/acme/projects", map[string]string{"slug": "web"}, 201, nil)
	c.call("POST", "/orgs/acme/configs", map[string]any{"kind": "issuer", "plugin": "local-ca", "name": "local", "config": map[string]any{}}, 201, nil)
	return &agentEnv{st: st, eng: eng, api: c, agentURL: agentURL}
}

func (e *agentEnv) runJobs(t *testing.T) {
	t.Helper()
	for {
		ran, err := e.eng.RunOne(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ran {
			return
		}
	}
}

type invite struct {
	Token, CASHA256, Command string
}

func TestAgentLifecycle(t *testing.T) {
	ctx := context.Background()
	e := newAgentEnv(t)
	root := t.TempDir()
	certDir := filepath.Join(root, "certs")
	stateDir := filepath.Join(root, "state")

	// Enroll. Shorten the identity lifetime so the first sync renews it.
	var inv invite
	e.api.call("POST", "/orgs/acme/projects/web/agents", map[string]any{"name": "web-01"}, 201, &inv)
	if !strings.Contains(inv.Command, inv.Token) || !strings.Contains(inv.Command, inv.CASHA256) {
		t.Fatalf("enroll command = %q", inv.Command)
	}
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{Server: e.agentURL, Token: inv.Token, CASHA256: strings.Repeat("00", 32),
		StateDir: filepath.Join(root, "evil")}); err == nil {
		t.Fatal("enrolled against a server with the wrong CA fingerprint")
	}
	agentca.ClientLifetime = 2 * time.Minute
	_, err := agent.Enroll(ctx, agent.EnrollOptions{Server: e.agentURL, Token: inv.Token, CASHA256: inv.CASHA256, StateDir: stateDir,
		AllowedPaths: []string{certDir}, AllowedCommands: [][]string{}})
	agentca.ClientLifetime = 90 * 24 * time.Hour
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{Server: e.agentURL, Token: inv.Token, CASHA256: inv.CASHA256,
		StateDir: filepath.Join(root, "again")}); err == nil {
		t.Fatal("enrollment token worked twice")
	}
	oldIdentity, _ := os.ReadFile(filepath.Join(stateDir, "identity.crt"))

	ag, err := agent.Open(stateDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ag.VerifyTimeout = 2 * time.Second

	// A certificate whose key lives on the agent, deployed like nginx.
	fullchain, key := filepath.Join(certDir, "www", "fullchain.pem"), filepath.Join(certDir, "www", "privkey.pem")
	os.MkdirAll(filepath.Dir(fullchain), 0o755)
	serverAddr := fileTLSServer(t, fullchain, key)
	e.api.call("POST", "/orgs/acme/projects/web/certificates", map[string]any{
		"name": "www", "names": []string{"www.example.com"}, "issuer": "local", "keyLocation": "agent"}, 201, nil)
	e.api.call("POST", "/orgs/acme/projects/web/targets", map[string]any{"name": "www-files", "agent": "web-01", "deployer": "files",
		"settings": map[string]any{"fullchainPath": fullchain, "keyPath": key, "verifyEndpoint": serverAddr}}, 201, nil)
	e.api.call("POST", "/orgs/acme/projects/web/targets", map[string]any{"name": "bad", "agent": "web-01", "deployer": "nginx",
		"settings": map[string]any{"keyPath": key}}, 400, nil) // nginx needs fullchainPath
	e.api.call("POST", "/orgs/acme/projects/web/certificates/www/targets", map[string]string{"target": "www-files"}, 204, nil)

	sync := func() {
		t.Helper()
		if _, err := ag.SyncOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	sync() // renews identity, sends a CSR
	newIdentity, _ := os.ReadFile(filepath.Join(stateDir, "identity.crt"))
	if bytes.Equal(oldIdentity, newIdentity) {
		t.Fatal("agent identity was not renewed")
	}
	oldLeaf, _ := certutil.ParseChainPEM(oldIdentity)
	if _, _, err := e.st.AgentByCertificate(ctx, agentca.CertFingerprint(oldLeaf[0])); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old agent certificate still accepted: %v", err)
	}

	e.runJobs(t) // the server issues for the agent's CSR
	sync()       // installs, verifies, queues the report
	sync()       // delivers the report

	var deps []struct {
		Target, Status, Message string
		Current                 bool
	}
	e.api.call("GET", "/orgs/acme/projects/web/certificates/www/deployments", nil, 200, &deps)
	if len(deps) != 1 || deps[0].Status != "done" || !deps[0].Current || !strings.Contains(deps[0].Message, "verified") {
		t.Fatalf("deployments = %+v", deps)
	}
	var view struct{ Current store.CertificateVersion }
	e.api.call("GET", "/orgs/acme/projects/web/certificates/www", nil, 200, &view)
	if view.Current.KeySecretID != "" {
		t.Fatal("server holds the agent's key")
	}
	firstKey, _ := os.ReadFile(key)
	if st, _ := os.Stat(key); st == nil {
		t.Fatal("key file missing")
	}

	// Manual renewal: the agent makes a new key.
	var renew map[string]string
	e.api.call("POST", "/orgs/acme/projects/web/certificates/www/renew", nil, 202, &renew)
	if renew["waitingFor"] != "agent" {
		t.Fatalf("renew = %v", renew)
	}
	sync()
	e.runJobs(t)
	sync()
	sync()
	secondKey, _ := os.ReadFile(key)
	if bytes.Equal(firstKey, secondKey) {
		t.Fatal("renewal reused the old key")
	}
	e.api.call("GET", "/orgs/acme/projects/web/certificates/www/deployments", nil, 200, &deps)
	if deps[0].Status != "done" || !deps[0].Current {
		t.Fatalf("after renewal: %+v", deps)
	}

	// A service that keeps serving the old certificate fails verification;
	// the previous files come back.
	staleDir := filepath.Join(certDir, "stale")
	os.MkdirAll(staleDir, 0o755)
	os.WriteFile(filepath.Join(staleDir, "fullchain.pem"), []byte("OLD CHAIN"), 0o644)
	os.WriteFile(filepath.Join(staleDir, "privkey.pem"), []byte("OLD KEY"), 0o600)
	e.api.call("POST", "/orgs/acme/projects/web/targets", map[string]any{"name": "stale", "agent": "web-01", "deployer": "files",
		"settings": map[string]any{"fullchainPath": filepath.Join(staleDir, "fullchain.pem"), "keyPath": filepath.Join(staleDir, "privkey.pem"),
			"verifyEndpoint": staticTLSServer(t)}}, 201, nil)
	// Paths outside the agent's allow-list and unlisted commands are refused.
	outside := filepath.Join(root, "outside")
	e.api.call("POST", "/orgs/acme/projects/web/targets", map[string]any{"name": "outside", "agent": "web-01", "deployer": "files",
		"settings": map[string]any{"fullchainPath": filepath.Join(outside, "f.pem"), "keyPath": filepath.Join(outside, "k.pem")}}, 201, nil)
	e.api.call("POST", "/orgs/acme/projects/web/targets", map[string]any{"name": "evil-cmd", "agent": "web-01", "deployer": "files",
		"settings": map[string]any{"fullchainPath": filepath.Join(certDir, "evil", "f.pem"), "keyPath": filepath.Join(certDir, "evil", "k.pem"),
			"reloadCommand": []string{"rm", "-rf", "/"}}}, 201, nil)
	for _, name := range []string{"stale", "outside", "evil-cmd"} {
		e.api.call("POST", "/orgs/acme/projects/web/certificates/www/targets", map[string]string{"target": name}, 204, nil)
	}
	sync()
	sync()

	if b, _ := os.ReadFile(filepath.Join(staleDir, "fullchain.pem")); string(b) != "OLD CHAIN" {
		t.Fatalf("stale target not rolled back: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(staleDir, "privkey.pem")); string(b) != "OLD KEY" {
		t.Fatal("stale key not rolled back")
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("agent wrote outside its allowed paths")
	}
	if _, err := os.Stat(filepath.Join(certDir, "evil")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("agent wrote files for a target with a forbidden command")
	}
	e.api.call("GET", "/orgs/acme/projects/web/certificates/www/deployments", nil, 200, &deps)
	want := map[string]string{"www-files": "done", "stale": "failed", "outside": "failed", "evil-cmd": "failed"}
	for _, d := range deps {
		if want[d.Target] != d.Status {
			t.Errorf("target %s: status %s (%s), want %s", d.Target, d.Status, d.Message, want[d.Target])
		}
	}

	// A certificate's key cannot be split across agents.
	var inv2 invite
	e.api.call("POST", "/orgs/acme/projects/web/agents", map[string]any{"name": "web-02"}, 201, &inv2)
	e.api.call("POST", "/orgs/acme/projects/web/targets", map[string]any{"name": "other-host", "agent": "web-02", "deployer": "files",
		"settings": map[string]any{"fullchainPath": "/etc/certower/f.pem", "keyPath": "/etc/certower/k.pem"}}, 201, nil)
	e.api.call("POST", "/orgs/acme/projects/web/certificates/www/targets", map[string]string{"target": "other-host"}, 409, nil)

	// Deleting the agent cuts it off.
	e.api.call("DELETE", "/orgs/acme/projects/web/agents/web-01", nil, 204, nil)
	if _, err := ag.SyncOnce(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("deleted agent still syncs: %v", err)
	}
}
