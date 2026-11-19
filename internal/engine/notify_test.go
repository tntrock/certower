package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/discovery"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

type recorder struct {
	mu     sync.Mutex
	events []plugin.Event
	fail   int // fail this many deliveries
}

func (r *recorder) all() []plugin.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]plugin.Event(nil), r.events...)
}

func (r *recorder) ofType(t plugin.EventType) []plugin.Event {
	var out []plugin.Event
	for _, e := range r.all() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

type recordingNotifier struct{ r *recorder }

func (n *recordingNotifier) Meta() plugin.Meta {
	return plugin.Meta{Name: "recorder", Kind: plugin.KindNotifier, ConfigSchema: json.RawMessage(`{"type":"object"}`)}
}
func (n *recordingNotifier) Configure(context.Context, json.RawMessage) error { return nil }
func (n *recordingNotifier) Notify(_ context.Context, e plugin.Event) error {
	n.r.mu.Lock()
	defer n.r.mu.Unlock()
	if n.r.fail > 0 {
		n.r.fail--
		return errors.New("receiver down")
	}
	n.r.events = append(n.r.events, e)
	return nil
}

func (te *testEnv) notifier(t *testing.T, name, config string) *store.PluginConfig {
	t.Helper()
	pc, err := te.e.Configs.Create(context.Background(), pluginconfig.CreateRequest{
		OrgID: te.org.ID, Kind: plugin.KindNotifier, Plugin: "recorder", Name: name, Config: json.RawMessage(config)})
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestIssueEvents(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.e.BaseURL = "https://certower.example.com/"
	te.notifier(t, "all", `{}`)
	te.ca.failNext = 2
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)

	failed := te.notes.ofType(plugin.EventIssueFailed)
	if len(failed) != 1 || failed[0].Severity != plugin.SeverityWarning {
		t.Fatalf("issue_failed events = %+v, want exactly one warning for two failed attempts", failed)
	}
	issued := te.notes.ofType(plugin.EventCertIssued)
	if len(issued) != 1 || issued[0].Org != "acme" || issued[0].Project != "shop" {
		t.Fatalf("cert.issued events = %+v", issued)
	}
	if issued[0].Link != "https://certower.example.com/o/acme/p/shop/certificates/www.example.com" {
		t.Errorf("link = %q", issued[0].Link)
	}
}

func TestExpiryWarnings(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.notifier(t, "all", `{}`)
	// Gets only critical expiry warnings.
	te.notifier(t, "pager", `{"minSeverity":"critical","events":["cert.expiring"]}`)
	te.ca.lifetime = 10 * 24 * time.Hour
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)
	v, _ := te.st.CurrentVersion(ctx, c.ID)

	// 10 days left: the 14-day warning, once.
	te.e.Now = time.Now
	te.e.checkExpiry(ctx)
	te.e.checkExpiry(ctx)
	te.drain(t)
	exp := te.notes.ofType(plugin.EventCertExpiring)
	if len(exp) != 1 || exp[0].Severity != plugin.SeverityWarning || !strings.Contains(exp[0].Subject, "10 days") {
		t.Fatalf("10 days left: %+v", exp)
	}

	// Two days left: critical, delivered to both notifiers.
	te.e.Now = func() time.Time { return v.NotAfter.Add(-36 * time.Hour) }
	te.e.checkExpiry(ctx)
	te.drain(t)
	exp = te.notes.ofType(plugin.EventCertExpiring)
	if len(exp) != 3 || exp[1].Severity != plugin.SeverityCritical || exp[2].Severity != plugin.SeverityCritical {
		t.Fatalf("2 days left: %+v", exp)
	}

	// Expired.
	te.e.Now = func() time.Time { return v.NotAfter.Add(time.Hour) }
	te.e.checkExpiry(ctx)
	te.drain(t)
	if exp = te.notes.ofType(plugin.EventCertExpiring); len(exp) != 5 || !strings.Contains(exp[4].Subject, "expired") {
		t.Fatalf("expired: %+v", exp)
	}
}

func TestNotifierRetries(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.notifier(t, "flaky", `{}`)
	te.notes.fail = 2
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)
	if got := te.notes.ofType(plugin.EventCertIssued); len(got) != 1 {
		t.Fatalf("event not delivered after retries: %+v", got)
	}

	te.notes.fail = 100
	te.e.Notify(ctx, te.org.ID, te.proj.ID, plugin.Event{Type: "test", Severity: plugin.SeverityInfo, Subject: "x"}, "")
	te.drain(t)
	jobs, _ := te.st.ListJobs(ctx, te.proj.ID, 50)
	for _, j := range jobs {
		if j.Type == JobNotify && j.Status == store.JobFailed && strings.Contains(j.LastError, "giving up") && j.Attempts == maxNotifyAttempts {
			return
		}
	}
	t.Fatalf("failing notifier was not given up on after %d attempts: %+v", maxNotifyAttempts, jobs)
}

func tlsServer(t *testing.T, chain [][]byte, key any) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}})
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

func TestScanLinksAndAlerts(t *testing.T) {
	ctx := context.Background()
	te := newTestEnv(t)
	te.notifier(t, "all", `{}`)
	roots := x509.NewCertPool()
	roots.AddCert(te.ca.cert)
	te.e.Scanner = &discovery.Scanner{Roots: roots}

	// A managed certificate served by a host.
	c := te.cert(t, "www.example.com")
	te.e.RequestIssue(ctx, c)
	te.drain(t)
	v, _ := te.st.CurrentVersion(ctx, c.ID)
	keyPEM, _ := te.e.Vault.Get(ctx, v.KeySecretID)
	key, _ := certutil.ParseKeyPEM(keyPEM)
	chain, _ := certutil.ParseChainPEM([]byte(v.ChainPEM))
	managedPort := tlsServer(t, [][]byte{chain[0].Raw, chain[1].Raw}, key)

	// An unmanaged, expired certificate somewhere else.
	k2, _ := certutil.GenerateKey(policy.ECDSAP256)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "old.example.com"}, DNSNames: []string{"old.example.com"},
		NotBefore: time.Now().Add(-100 * 24 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, te.ca.cert, k2.Public(), te.ca.key)
	oldPort := tlsServer(t, [][]byte{der, te.ca.cert.Raw}, k2)

	managed, _ := te.st.CreateEndpoint(ctx, store.DiscoveryEndpoint{OrgID: te.org.ID, Host: "127.0.0.1", Port: managedPort, SNI: "www.example.com"})
	old, _ := te.st.CreateEndpoint(ctx, store.DiscoveryEndpoint{OrgID: te.org.ID, ProjectID: te.proj.ID, Host: "127.0.0.1", Port: oldPort, SNI: "old.example.com"})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	dead, _ := te.st.CreateEndpoint(ctx, store.DiscoveryEndpoint{OrgID: te.org.ID, Host: "127.0.0.1", Port: closedPort})

	te.e.Now = time.Now
	if err := te.e.scheduleScans(ctx); err != nil {
		t.Fatal(err)
	}
	te.drain(t)

	got, err := te.st.LatestDiscovered(ctx, managed.ID)
	if err != nil || got.VersionID != v.ID || !jsonEmpty(got.Findings) {
		t.Fatalf("managed endpoint: %+v %v", got, err)
	}
	got, _ = te.st.LatestDiscovered(ctx, old.ID)
	if got.VersionID != "" || !strings.Contains(string(got.Findings), discovery.CodeExpired) {
		t.Fatalf("unmanaged endpoint: %+v", got)
	}
	ep, _ := te.st.GetEndpoint(ctx, te.org.ID, dead.ID)
	if ep.LastScannedAt == nil || ep.LastError == "" {
		t.Fatalf("closed port: %+v", ep)
	}

	alerts := te.notes.ofType(plugin.EventDiscoveryAlert)
	if len(alerts) != 1 || !strings.Contains(alerts[0].Subject, "expired") {
		t.Fatalf("alerts = %+v", alerts)
	}
	// Scanning again does not repeat the alert.
	te.e.RequestScan(ctx, old)
	te.drain(t)
	if n := len(te.notes.ofType(plugin.EventDiscoveryAlert)); n != 1 {
		t.Fatalf("alert repeated: %d", n)
	}
}

func jsonEmpty(raw []byte) bool {
	var v []any
	return json.Unmarshal(raw, &v) == nil && len(v) == 0
}
