package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Store, *Organization, *Project) {
	t.Helper()
	s := openTest(t)
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, "acme", "ACME")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateProject(ctx, org.ID, "shop", "Shop")
	if err != nil {
		t.Fatal(err)
	}
	return s, org, p
}

func TestPluginConfigLookup(t *testing.T) {
	ctx := context.Background()
	s, org, p := fixture(t)
	shared, err := s.CreatePluginConfig(ctx, PluginConfig{OrgID: org.ID, Kind: "issuer", Plugin: "acme", Name: "le", Config: []byte(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	// Org-wide names are unique even though project_id is NULL.
	if _, err := s.CreatePluginConfig(ctx, PluginConfig{OrgID: org.ID, Kind: "issuer", Plugin: "acme", Name: "le", Config: []byte(`{}`)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate org-wide config: err = %v", err)
	}
	got, err := s.FindPluginConfig(ctx, org.ID, p.ID, "issuer", "le")
	if err != nil || got.ID != shared.ID {
		t.Fatalf("inherited lookup = %v, %v", got, err)
	}
	own, _ := s.CreatePluginConfig(ctx, PluginConfig{OrgID: org.ID, ProjectID: p.ID, Kind: "issuer", Plugin: "acme", Name: "le", Config: []byte(`{}`)})
	got, _ = s.FindPluginConfig(ctx, org.ID, p.ID, "issuer", "le")
	if got.ID != own.ID {
		t.Fatal("project config does not override org-wide config")
	}
	all, _ := s.ListPluginConfigs(ctx, org.ID, p.ID)
	orgOnly, _ := s.ListPluginConfigs(ctx, org.ID, "")
	if len(all) != 2 || len(orgOnly) != 1 {
		t.Fatalf("list: project view %d, org view %d", len(all), len(orgOnly))
	}

	// A config in use cannot be deleted.
	if _, err := s.CreateCertificate(ctx, Certificate{ProjectID: p.ID, Name: "www", Names: []string{"www.example.com"},
		KeyType: "ecdsa-p256", IssuerConfigID: shared.ID, KeyLocation: "server"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePluginConfig(ctx, shared.ID); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("delete config in use: err = %v", err)
	}
}

func TestCertificatesAndVersions(t *testing.T) {
	ctx := context.Background()
	s, org, p := fixture(t)
	iss, _ := s.CreatePluginConfig(ctx, PluginConfig{OrgID: org.ID, Kind: "issuer", Plugin: "acme", Name: "le", Config: []byte(`{}`)})
	c, err := s.CreateCertificate(ctx, Certificate{ProjectID: p.ID, Name: "www", Names: []string{"www.example.com", "example.com"},
		KeyType: "ecdsa-p256", IssuerConfigID: iss.ID, KeyLocation: "server"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != CertPending || c.RenewBeforeRatio == 0 {
		t.Fatalf("new cert = %+v", c)
	}
	now := time.Now()
	due, _ := s.CertificatesDue(ctx, now, 10)
	if len(due) != 1 {
		t.Fatalf("never-issued cert not due: %v", due)
	}

	v, err := s.InsertCertificateVersion(ctx, CertificateVersion{CertificateID: c.ID, Serial: "01", Fingerprint: "fp1", ARICertID: "ari1",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour), RenewAfter: now.Add(60 * 24 * time.Hour), ChainPEM: "pem"})
	if err != nil {
		t.Fatal(err)
	}
	if due, _ := s.CertificatesDue(ctx, now, 10); len(due) != 0 {
		t.Fatalf("freshly issued cert is due: %v", due)
	}
	if due, _ := s.CertificatesDue(ctx, now.Add(61*24*time.Hour), 10); len(due) != 1 {
		t.Fatal("cert past renew_after is not due")
	}

	cur, err := s.CurrentVersion(ctx, c.ID)
	if err != nil || cur.ID != v.ID || cur.ARICertID != "ari1" || cur.RevokedAt != nil {
		t.Fatalf("CurrentVersion = %+v, %v", cur, err)
	}
	checks, _ := s.VersionsForARICheck(ctx, now.Add(time.Hour), 10)
	if len(checks) != 1 {
		t.Fatalf("ARI check candidates = %d", len(checks))
	}
	if err := s.UpdateVersionRenewal(ctx, v.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if checks, _ := s.VersionsForARICheck(ctx, now.Add(-time.Minute), 10); len(checks) != 0 {
		t.Fatal("just-checked version offered again")
	}

	if err := s.MarkVersionRevoked(ctx, v.ID, 4); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkVersionRevoked(ctx, v.ID, 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: err = %v", err)
	}
	if _, err := s.CurrentVersion(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked version is still current")
	}
	got, _ := s.GetVersion(ctx, c.ID, v.ID)
	if got.RevokedAt == nil || *got.RevokeReason != 4 {
		t.Fatalf("revoked version = %+v", got)
	}
	if due, _ := s.CertificatesDue(ctx, now, 10); len(due) != 1 {
		t.Fatal("cert with only revoked versions is not due")
	}
	s.SetCertificateStatus(ctx, c.ID, CertInvalid, "policy")
	if due, _ := s.CertificatesDue(ctx, now, 10); len(due) != 0 {
		t.Fatal("invalid cert is due")
	}
}

func TestJobQueue(t *testing.T) {
	ctx := context.Background()
	s, _, p := fixture(t)

	j, created, err := s.EnqueueJob(ctx, Job{ProjectID: p.ID, Type: "issue", DedupeKey: "issue:c1"})
	if err != nil || !created {
		t.Fatal(err)
	}
	dup, created, err := s.EnqueueJob(ctx, Job{ProjectID: p.ID, Type: "issue", DedupeKey: "issue:c1"})
	if err != nil || created || dup.ID != j.ID {
		t.Fatalf("duplicate enqueue = %+v, %v, %v", dup, created, err)
	}
	s.EnqueueJob(ctx, Job{Type: "later", RunAfter: time.Now().Add(time.Hour)})

	claimed, err := s.ClaimJob(ctx, "w1", time.Minute)
	if err != nil || claimed.ID != j.ID || claimed.Attempts != 1 || claimed.Status != JobRunning {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	if _, err := s.ClaimJob(ctx, "w2", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second claim: err = %v (future job must not run, running job is leased)", err)
	}

	// Retry, then complete; after that the dedupe key is free again.
	if err := s.RetryJob(ctx, j.ID, time.Now().Add(-time.Second), "boom"); err != nil {
		t.Fatal(err)
	}
	again, err := s.ClaimJob(ctx, "w1", time.Minute)
	if err != nil || again.Attempts != 2 || again.LastError != "boom" {
		t.Fatalf("reclaim = %+v, %v", again, err)
	}
	if err := s.CompleteJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	if _, created, _ := s.EnqueueJob(ctx, Job{Type: "issue", DedupeKey: "issue:c1"}); !created {
		t.Fatal("dedupe key still held by a finished job")
	}

	// A job whose worker died is reclaimed after its lease expires.
	crashed, _ := s.ClaimJob(ctx, "dead", -time.Second)
	if crashed == nil {
		t.Fatal("nothing to claim")
	}
	rescued, err := s.ClaimJob(ctx, "w3", time.Minute)
	if err != nil || rescued.ID != crashed.ID {
		t.Fatalf("expired lease not reclaimed: %+v, %v", rescued, err)
	}
	jobs, _ := s.ListJobs(ctx, p.ID, 10)
	if len(jobs) != 1 {
		t.Fatalf("ListJobs = %d", len(jobs))
	}
}

func TestSecretRows(t *testing.T) {
	ctx := context.Background()
	s, org, _ := fixture(t)
	id := NewID()
	if err := s.CreateSecret(ctx, SecretRow{ID: id, OrgID: org.ID, Name: "x", KEKID: "local:1", WrappedDEK: []byte{1}, Ciphertext: []byte{2}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSecret(ctx, id)
	if err != nil || got.KEKID != "local:1" || got.Ciphertext[0] != 2 {
		t.Fatalf("GetSecret = %+v, %v", got, err)
	}
	if err := s.CreateSecret(ctx, SecretRow{ID: NewID(), OrgID: org.ID, Name: "x", KEKID: "k", WrappedDEK: []byte{1}, Ciphertext: []byte{2}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate org-wide secret name: err = %v", err)
	}
	if err := s.DeleteSecret(ctx, id); err != nil {
		t.Fatal(err)
	}
}
