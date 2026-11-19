package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAgentEnrollment(t *testing.T) {
	ctx := context.Background()
	s, _, p := fixture(t)
	inv, err := s.CreateAgentInvitation(ctx, p.ID, "web-01", []byte("token"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Enrolled || inv.EnrollExpiresAt == nil {
		t.Fatalf("invitation = %+v", inv)
	}
	if _, err := s.CreateAgentInvitation(ctx, p.ID, "web-01", []byte("other"), time.Now().Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate agent name: %v", err)
	}
	s.CreateAgentInvitation(ctx, p.ID, "old", []byte("expired"), time.Now().Add(-time.Minute))
	if _, err := s.EnrollAgent(ctx, []byte("expired"), "fp0", "h", "linux", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token: %v", err)
	}

	a, err := s.EnrollAgent(ctx, []byte("token"), "fp1", "web01.example.com", "linux", "0.1")
	if err != nil || !a.Enrolled || a.Hostname != "web01.example.com" {
		t.Fatalf("enroll = %+v, %v", a, err)
	}
	if _, err := s.EnrollAgent(ctx, []byte("token"), "fp2", "h", "linux", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token reused: %v", err)
	}

	// Identity renewal: both certificates work until the new one is used.
	if err := s.SetAgentNextCertificate(ctx, a.ID, "fp1b"); err != nil {
		t.Fatal(err)
	}
	if got, next, err := s.AgentByCertificate(ctx, "fp1"); err != nil || next || got.ID != a.ID {
		t.Fatalf("old cert: %v %v %v", got, next, err)
	}
	if _, next, _ := s.AgentByCertificate(ctx, "fp1b"); !next {
		t.Fatal("new cert not reported as next")
	}
	s.PromoteAgentCertificate(ctx, a.ID)
	if _, _, err := s.AgentByCertificate(ctx, "fp1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old certificate still accepted after promotion")
	}
	if _, next, err := s.AgentByCertificate(ctx, "fp1b"); err != nil || next {
		t.Fatalf("promoted cert: next=%v err=%v", next, err)
	}

	if err := s.TouchAgent(ctx, a.ID, "web01", "linux", "0.2"); err != nil {
		t.Fatal(err)
	}
	agents, _ := s.ListAgents(ctx, p.ID)
	if len(agents) != 2 || agents[1].Version != "0.2" || agents[1].LastSeenAt == nil {
		t.Fatalf("agents = %+v", agents)
	}
}

func TestTargetsAndDeployments(t *testing.T) {
	ctx := context.Background()
	s, org, p := fixture(t)
	s.CreateAgentInvitation(ctx, p.ID, "web-01", []byte("tok"), time.Now().Add(time.Hour))
	a, _ := s.EnrollAgent(ctx, []byte("tok"), "fp", "h", "linux", "1")
	iss, _ := s.CreatePluginConfig(ctx, PluginConfig{OrgID: org.ID, Kind: "issuer", Plugin: "acme", Name: "le", Config: []byte(`{}`)})
	c, _ := s.CreateCertificate(ctx, Certificate{ProjectID: p.ID, Name: "www", Names: []string{"www.example.com"},
		KeyType: "ecdsa-p256", IssuerConfigID: iss.ID, KeyLocation: "agent"})

	tg, err := s.CreateTarget(ctx, Target{ProjectID: p.ID, Name: "nginx-web01", AgentID: a.ID, Deployer: "nginx",
		Settings: []byte(`{"fullchainPath":"/etc/certower/www.pem"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AttachTarget(ctx, c.ID, tg.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachTarget(ctx, c.ID, tg.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("double attach: %v", err)
	}
	certs, _ := s.CertificatesForAgent(ctx, a.ID)
	targets, _ := s.TargetsForCertificate(ctx, c.ID)
	if len(certs) != 1 || len(targets) != 1 || !jsonEqual(t, targets[0].Settings, `{"fullchainPath":"/etc/certower/www.pem"}`) {
		t.Fatalf("certs %v targets %v", certs, targets)
	}

	// Agent-key certificates are not scheduled by the server.
	if due, _ := s.CertificatesDue(ctx, time.Now(), 10); len(due) != 0 {
		t.Fatalf("agent certificate scheduled: %v", due)
	}
	if err := s.RequestRenewal(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetCertificate(ctx, c.ID); got.RenewRequestedAt == nil {
		t.Fatal("renewal request not stored")
	}

	v, _ := s.InsertCertificateVersion(ctx, CertificateVersion{CertificateID: c.ID, Serial: "1", Fingerprint: "f",
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), RenewAfter: time.Now(), ChainPEM: "x"})
	s.RecordDeployment(ctx, Deployment{VersionID: v.ID, TargetID: tg.ID, Status: "failed", Message: "reload failed"})
	s.RecordDeployment(ctx, Deployment{VersionID: v.ID, TargetID: tg.ID, Status: "done"})
	ds, _ := s.DeploymentsForCertificate(ctx, c.ID)
	if len(ds) != 1 || ds[0].Status != "done" || ds[0].Message != "" {
		t.Fatalf("deployments = %+v", ds)
	}

	// Deleting the agent removes its targets.
	s.DeleteAgent(ctx, a.ID)
	if targets, _ := s.TargetsForCertificate(ctx, c.ID); len(targets) != 0 {
		t.Fatal("targets survived agent deletion")
	}
}

func TestServerKeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	k := ServerKey{Name: "agent-ca", CertPEM: "pem", KEKID: "k", WrappedDEK: []byte{1}, Ciphertext: []byte{2}}
	if err := s.CreateServerKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateServerKey(ctx, k); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := s.GetServerKey(ctx, "agent-ca")
	if err != nil || got.CertPEM != "pem" {
		t.Fatalf("GetServerKey = %+v, %v", got, err)
	}
}
