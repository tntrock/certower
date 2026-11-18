package pluginconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

type fakeConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
	Auth  struct {
		Key string `json:"key"`
	} `json:"auth"`
}

// fake is a DNS plugin with a top-level and a nested secret, and a
// generated field.
type fake struct{ cfg fakeConfig }

func (f *fake) Meta() plugin.Meta {
	return plugin.Meta{Name: "fake", Kind: plugin.KindDNS, ConfigSchema: json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {"type": "string"},
			"token": {"type": "string", "x-secret": true},
			"auth": {"type": "object", "properties": {"key": {"type": "string", "x-secret": true}}}
		}}`)}
}

func (f *fake) PrepareConfig(_ context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var m map[string]any
	json.Unmarshal(raw, &m)
	if m["url"] == nil {
		m["url"] = "https://generated.example"
	}
	return json.Marshal(m)
}

func (f *fake) Configure(_ context.Context, raw json.RawMessage) error {
	var c fakeConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if c.Token == "" {
		return errors.New("token is required")
	}
	f.cfg = c
	return nil
}

func (f *fake) Present(string, string, string) error { return nil }
func (f *fake) CleanUp(string, string, string) error { return nil }

func setup(t *testing.T) (*Service, *store.Organization, *store.Project) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite:"+filepath.Join(t.TempDir(), "pc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kek, _ := secrets.NewLocalKEK(bytes.Repeat([]byte{1}, 32))
	reg := plugin.NewRegistry()
	reg.Register(func() plugin.Plugin { return &fake{} })
	org, _ := st.CreateOrganization(ctx, "acme", "ACME")
	p, _ := st.CreateProject(ctx, org.ID, "shop", "Shop")
	return &Service{Store: st, Vault: &secrets.Vault{Store: st, KEK: kek}, Registry: reg}, org, p
}

func TestCreateSealsSecrets(t *testing.T) {
	ctx := context.Background()
	svc, org, p := setup(t)
	pc, err := svc.Create(ctx, CreateRequest{OrgID: org.ID, ProjectID: p.ID, Kind: plugin.KindDNS, Plugin: "fake", Name: "dns",
		Config: json.RawMessage(`{"token":"top-secret","auth":{"key":"nested-secret"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	stored := string(pc.Config)
	if strings.Contains(stored, "top-secret") || strings.Contains(stored, "nested-secret") {
		t.Fatalf("plaintext secret stored: %s", stored)
	}
	if !strings.Contains(stored, "generated.example") {
		t.Fatalf("PrepareConfig result not stored: %s", stored)
	}
	red := string(Redact(*pc).Config)
	if strings.Contains(red, "$secret") || strings.Count(red, Redacted) != 2 {
		t.Fatalf("redacted = %s", red)
	}

	p2, err := svc.Instantiate(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	got := p2.(*fake).cfg
	if got.Token != "top-secret" || got.Auth.Key != "nested-secret" {
		t.Fatalf("resolved config = %+v", got)
	}

	if err := svc.Delete(ctx, pc); err != nil {
		t.Fatal(err)
	}
	for _, id := range secretIDs(pc.Config) {
		if _, err := svc.Store.GetSecret(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("secret %s survived config deletion", id)
		}
	}
}

func TestCreateRejects(t *testing.T) {
	ctx := context.Background()
	svc, org, _ := setup(t)
	for name, req := range map[string]CreateRequest{
		"unknown plugin": {OrgID: org.ID, Kind: plugin.KindDNS, Plugin: "nope", Name: "x", Config: json.RawMessage(`{}`)},
		"plugin rejects": {OrgID: org.ID, Kind: plugin.KindDNS, Plugin: "fake", Name: "x", Config: json.RawMessage(`{}`)},
		"secret ref":     {OrgID: org.ID, Kind: plugin.KindDNS, Plugin: "fake", Name: "x", Config: json.RawMessage(`{"token":"t","auth":{"key":{"$secret":"someone-elses"}}}`)},
	} {
		if _, err := svc.Create(ctx, req); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestCrossTenantSecretRefused(t *testing.T) {
	ctx := context.Background()
	svc, org, p := setup(t)
	other, _ := svc.Store.CreateOrganization(ctx, "evil", "Evil")
	victim, err := svc.Create(ctx, CreateRequest{OrgID: org.ID, ProjectID: p.ID, Kind: plugin.KindDNS, Plugin: "fake", Name: "dns",
		Config: json.RawMessage(`{"token":"victim-token"}`)})
	if err != nil {
		t.Fatal(err)
	}
	// A config row in another org pointing at the victim's secret, as if
	// written directly to the database.
	forged := *victim
	forged.ID, forged.OrgID, forged.ProjectID = store.NewID(), other.ID, ""
	if _, err := svc.Instantiate(ctx, &forged); !errors.Is(err, secrets.ErrOutOfScope) {
		t.Fatalf("cross-tenant resolve: err = %v, want ErrOutOfScope", err)
	}
}
