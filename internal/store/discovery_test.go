package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDiscoveryStore(t *testing.T) {
	ctx := context.Background()
	s, org, p := fixture(t)
	e, err := s.CreateEndpoint(ctx, DiscoveryEndpoint{OrgID: org.ID, ProjectID: p.ID, Host: "www.example.com", Port: 443, SNI: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEndpoint(ctx, DiscoveryEndpoint{OrgID: org.ID, Host: "www.example.com", Port: 443, SNI: "www.example.com"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate endpoint: %v", err)
	}
	due, _ := s.EndpointsDue(ctx, time.Now(), 10)
	if len(due) != 1 {
		t.Fatalf("never-scanned endpoint not due: %v", due)
	}
	s.RecordScan(ctx, e.ID, "")
	if due, _ := s.EndpointsDue(ctx, time.Now().Add(-time.Hour), 10); len(due) != 0 {
		t.Fatal("just-scanned endpoint is due")
	}

	d := DiscoveredCert{EndpointID: e.ID, Fingerprint: "fp1", Subject: "www", Issuer: "CA", Names: []string{"www.example.com"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Findings: []byte(`[{"code":"expiring_soon"}]`)}
	if isNew, err := s.UpsertDiscovered(ctx, d); err != nil || !isNew {
		t.Fatalf("first sighting: new=%v err=%v", isNew, err)
	}
	d.Findings = []byte(`[]`)
	if isNew, _ := s.UpsertDiscovered(ctx, d); isNew {
		t.Fatal("second sighting reported as new")
	}
	got, err := s.LatestDiscovered(ctx, e.ID)
	if err != nil || got.Fingerprint != "fp1" || !jsonEqual(t, got.Findings, `[]`) || got.Names[0] != "www.example.com" {
		t.Fatalf("latest = %+v, %v", got, err)
	}

	first, err := s.LogNotification(ctx, "expiring:v1:7")
	again, _ := s.LogNotification(ctx, "expiring:v1:7")
	if err != nil || !first || again {
		t.Fatalf("notification log: first=%v again=%v err=%v", first, again, err)
	}
}
