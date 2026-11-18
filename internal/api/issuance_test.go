package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

var testSerial atomic.Int64

// testIssuerPlugin signs with a throwaway CA. Its config has a secret
// field so redaction is exercised.
type testIssuerPlugin struct{ ca *testCA }

type testCA struct {
	cert *x509.Certificate
	key  any
}

func newTestCA(t *testing.T) *testCA {
	key, _ := certutil.GenerateKey(policy.ECDSAP256)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1, 2, 3},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key}
}

func (p *testIssuerPlugin) Meta() plugin.Meta {
	return plugin.Meta{Name: "test-ca", Kind: plugin.KindIssuer, ConfigSchema: json.RawMessage(
		`{"type":"object","properties":{"apiKey":{"type":"string","x-secret":true}}}`)}
}

func (p *testIssuerPlugin) Configure(_ context.Context, raw json.RawMessage) error {
	var c struct {
		APIKey string `json:"apiKey"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if c.APIKey != "ca-api-key" {
		return errors.New("wrong apiKey")
	}
	return nil
}

func (p *testIssuerPlugin) Issue(_ context.Context, req plugin.IssueRequest, _ plugin.ChallengeSolvers) (*plugin.IssuedCertificate, error) {
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, err
	}
	nb := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(100 + testSerial.Add(1)), Subject: csr.Subject, DNSNames: csr.DNSNames,
		NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca.cert, csr.PublicKey, p.ca.key)
	if err != nil {
		return nil, err
	}
	return &plugin.IssuedCertificate{Chain: [][]byte{der, p.ca.cert.Raw}, NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}, nil
}

func (p *testIssuerPlugin) Revoke(context.Context, []byte, int) error { return nil }
func (p *testIssuerPlugin) RenewalInfo(context.Context, []byte) (*plugin.RenewalWindow, error) {
	return nil, plugin.ErrNotSupported
}

func testRegistry(t *testing.T) *plugin.Registry {
	ca := newTestCA(t)
	reg := plugin.NewRegistry()
	reg.Register(func() plugin.Plugin { return &testIssuerPlugin{ca: ca} })
	return reg
}

// raw sends a request and returns the status and body.
func (e *env) raw(token, method, path string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) runJobs() {
	e.t.Helper()
	for i := 0; i < 10; i++ {
		ran, err := e.eng.RunOne(context.Background())
		if err != nil {
			e.t.Fatal(err)
		}
		if !ran {
			return
		}
	}
}

func TestIssuanceAPI(t *testing.T) {
	e := newEnv(t)
	root := e.user("root@example.com", true)
	boss := e.user("boss@example.com", false)
	ops := e.user("ops@example.com", false)
	viewer := e.user("viewer@example.com", false)
	e.do(root, "POST", "/api/v1/orgs", slugName{Slug: "acme"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/bindings", createBindingRequest{Role: "org_admin", User: "boss@example.com"}, 201, nil)
	e.do(boss, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "shop"}, 201, nil)
	e.do(boss, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "erp"}, 201, nil)
	e.do(boss, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "operator", User: "ops@example.com"}, 201, nil)
	e.do(boss, "POST", "/api/v1/orgs/acme/projects/shop/bindings", createBindingRequest{Role: "viewer", User: "viewer@example.com"}, 201, nil)

	var plugins map[string][]plugin.Meta
	e.do(ops, "GET", "/api/v1/plugins", nil, 200, &plugins)
	if len(plugins["issuer"]) != 1 {
		t.Fatalf("plugins = %v", plugins)
	}

	// An org-wide issuer, created by the org admin. Operators cannot.
	cfg := createConfigRequest{Kind: plugin.KindIssuer, Plugin: "test-ca", Name: "corp-ca", Config: json.RawMessage(`{"apiKey":"ca-api-key"}`)}
	e.do(ops, "POST", "/api/v1/orgs/acme/configs", cfg, 403, nil)
	e.do(boss, "POST", "/api/v1/orgs/acme/configs", createConfigRequest{Kind: plugin.KindIssuer, Plugin: "test-ca", Name: "bad", Config: json.RawMessage(`{"apiKey":"nope"}`)}, 400, nil)
	var created store.PluginConfig
	e.do(boss, "POST", "/api/v1/orgs/acme/configs", cfg, 201, &created)
	if strings.Contains(string(created.Config), "ca-api-key") {
		t.Fatalf("secret echoed back: %s", created.Config)
	}
	status, body := e.raw(viewer, "GET", "/api/v1/orgs/acme/projects/shop/configs")
	if status != 200 || !strings.Contains(body, "corp-ca") || strings.Contains(body, "ca-api-key") {
		t.Fatalf("project view of configs: %d %s", status, body)
	}

	// Policy limits the shop project to its own names.
	e.do(boss, "PUT", "/api/v1/orgs/acme/projects/shop/policy", map[string]any{"allowedNames": []string{"*.shop.example.com"}}, 200, nil)

	certReq := createCertificateRequest{Name: "www", Names: []string{"WWW.Shop.Example.com.", "www.shop.example.com"}, Issuer: "corp-ca"}
	e.do(viewer, "POST", "/api/v1/orgs/acme/projects/shop/certificates", certReq, 403, nil)
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates", createCertificateRequest{Name: "x", Names: []string{"evil.com"}, Issuer: "corp-ca"}, 422, nil)
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates", createCertificateRequest{Name: "x", Names: []string{"a.shop.example.com"}, Issuer: "nope"}, 404, nil)
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates", createCertificateRequest{Name: "x", Names: []string{"a.shop.example.com"}, Issuer: "corp-ca", KeyType: "dsa"}, 400, nil)

	var accepted struct {
		Certificate store.Certificate
		Job         store.Job
	}
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates", certReq, 202, &accepted)
	if len(accepted.Certificate.Names) != 1 || accepted.Certificate.Names[0] != "www.shop.example.com" || accepted.Job.Status != "queued" {
		t.Fatalf("accepted = %+v", accepted)
	}
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates", certReq, 409, nil)

	e.runJobs()

	var view certificateView
	e.do(viewer, "GET", "/api/v1/orgs/acme/projects/shop/certificates/www", nil, 200, &view)
	if view.Status != "active" || view.Current == nil {
		t.Fatalf("certificate view = %+v", view)
	}
	status, body = e.raw(viewer, "GET", "/api/v1/orgs/acme/projects/shop/certificates/www/versions/current/chain.pem")
	if status != 200 || strings.Count(body, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("chain download: %d %s", status, body)
	}
	chain, _ := certutil.ParseChainPEM([]byte(body))
	if chain[0].DNSNames[0] != "www.shop.example.com" {
		t.Fatalf("issued names = %v", chain[0].DNSNames)
	}

	// Private keys are exportable only with an explicit key.export grant.
	if status, _ := e.raw(ops, "GET", "/api/v1/orgs/acme/projects/shop/certificates/www/versions/current/key.pem"); status != 403 {
		t.Fatalf("operator key export: %d", status)
	}
	if status, _ := e.raw(root, "GET", "/api/v1/orgs/acme/projects/shop/certificates/www/versions/current/key.pem"); status != 403 {
		t.Fatalf("superuser key export without grant: %d", status)
	}
	e.do(boss, "POST", "/api/v1/orgs/acme/roles", createRoleRequest{Name: "key-custodian", Permissions: []rbac.Permission{"key.export"}}, 201, nil)
	// No API caller holds key.export, so nobody can grant it through the
	// API; an operator of the instance binds it in the database.
	if _, err := e.st.CreateRoleBinding(context.Background(), store.RoleBinding{OrgID: orgID(t, e), ProjectID: view.ProjectID, Role: "key-custodian", UserID: userID(t, e, "ops@example.com")}); err != nil {
		t.Fatal(err)
	}
	status, body = e.raw(ops, "GET", "/api/v1/orgs/acme/projects/shop/certificates/www/versions/current/key.pem")
	if status != 200 || !strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("key export with grant: %d", status)
	}
	var audit []store.AuditEntry
	e.do(boss, "GET", "/api/v1/orgs/acme/audit?limit=1", nil, 200, &audit)
	if audit[0].Action != "key.export" {
		t.Fatalf("key export not audited: %+v", audit[0])
	}

	// Other projects cannot see the certificate.
	e.do(ops, "GET", "/api/v1/orgs/acme/projects/erp/certificates/www", nil, 404, nil)

	// Renew queues one job; revoke works once.
	var job store.Job
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates/www/renew", nil, 202, &job)
	e.runJobs()
	var versions []store.CertificateVersion
	e.do(viewer, "GET", "/api/v1/orgs/acme/projects/shop/certificates/www/versions", nil, 200, &versions)
	if len(versions) != 2 {
		t.Fatalf("versions = %d, want 2", len(versions))
	}
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates/www/revoke", revokeRequest{Reason: 2}, 400, nil)
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates/www/revoke", revokeRequest{Reason: 4, Version: versions[1].ID}, 204, nil)
	e.do(ops, "POST", "/api/v1/orgs/acme/projects/shop/certificates/www/revoke", revokeRequest{Reason: 4, Version: versions[1].ID}, 409, nil)

	var jobs []store.Job
	e.do(viewer, "GET", "/api/v1/orgs/acme/projects/shop/jobs", nil, 200, &jobs)
	if len(jobs) != 2 || jobs[0].Status != "done" {
		t.Fatalf("jobs = %+v", jobs)
	}

	// A config in use cannot be deleted; after deleting the certificate it can.
	e.do(boss, "DELETE", "/api/v1/orgs/acme/configs/"+created.ID, nil, 409, nil)
	e.do(boss, "DELETE", "/api/v1/orgs/acme/projects/shop/configs/"+created.ID, nil, 404, nil)
	e.do(ops, "DELETE", "/api/v1/orgs/acme/projects/shop/certificates/www", nil, 204, nil)
	e.do(boss, "DELETE", "/api/v1/orgs/acme/configs/"+created.ID, nil, 204, nil)
}

func orgID(t *testing.T, e *env) string {
	o, err := e.st.GetOrganizationBySlug(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

func userID(t *testing.T, e *env, email string) string {
	u, err := e.st.GetUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}
