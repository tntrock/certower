package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/policy"
)

// openTest opens a fresh migrated database. Set CERTOWER_TEST_POSTGRES to a
// postgres:// DSN to run against PostgreSQL instead; each test then gets its
// own schema in that database.
func openTest(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("CERTOWER_TEST_POSTGRES")
	if dsn == "" {
		dsn = "sqlite:" + filepath.Join(t.TempDir(), "test.db")
	} else {
		dsn = postgresSchema(t, dsn)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := openTest(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRebind(t *testing.T) {
	s := &Store{dialect: Postgres}
	got := s.rebind("SELECT a FROM t WHERE b = ? AND c = ?")
	if want := "SELECT a FROM t WHERE b = $1 AND c = $2"; got != want {
		t.Errorf("rebind = %q, want %q", got, want)
	}
}

func TestTenancy(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	org, err := s.CreateOrganization(ctx, "acme", "ACME Corp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrganization(ctx, "acme", "dup"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate slug: err = %v, want ErrConflict", err)
	}
	got, err := s.GetOrganizationBySlug(ctx, "acme")
	if err != nil || got.ID != org.ID || !got.CreatedAt.Equal(org.CreatedAt) {
		t.Fatalf("GetOrganizationBySlug = %+v, %v; want %+v", got, err, org)
	}
	if _, err := s.GetOrganizationBySlug(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing org: err = %v", err)
	}

	p, err := s.CreateProject(ctx, org.ID, "shop", "Shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "00000000-0000-0000-0000-000000000000", "x", "x"); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("project in missing org: err = %v, want ErrInvalidReference", err)
	}

	pol := policy.Policy{AllowedNames: []string{"*.shop.example.com"}, MaxValidityDays: 90}
	if err := s.PutPolicy(ctx, p.ID, pol); err != nil {
		t.Fatal(err)
	}
	pol.MaxValidityDays = 47
	if err := s.PutPolicy(ctx, p.ID, pol); err != nil {
		t.Fatal(err)
	}
	back, err := s.GetPolicy(ctx, p.ID)
	if err != nil || back.MaxValidityDays != 47 || back.AllowedNames[0] != "*.shop.example.com" {
		t.Fatalf("GetPolicy = %+v, %v", back, err)
	}

	if err := s.DeleteProject(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProject(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: err = %v", err)
	}
}

func TestSessionsAndTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, err := s.CreateUser(ctx, "a@example.com", "A", "hash", false)
	if err != nil {
		t.Fatal(err)
	}

	live, expired := []byte("live-token-hash"), []byte("old-token-hash")
	s.CreateSession(ctx, u.ID, live, time.Now().Add(time.Hour))
	s.CreateSession(ctx, u.ID, expired, time.Now().Add(-time.Minute))
	if got, err := s.SessionUser(ctx, live); err != nil || got.ID != u.ID {
		t.Fatalf("SessionUser(live) = %v, %v", got, err)
	}
	if _, err := s.SessionUser(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SessionUser(expired) err = %v", err)
	}

	org, _ := s.CreateOrganization(ctx, "acme", "ACME")
	p, _ := s.CreateProject(ctx, org.ID, "shop", "Shop")
	sa, err := s.CreateServiceAccount(ctx, p.ID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	s.CreateAPIToken(ctx, sa.ID, []byte("tok"), nil)
	s.CreateAPIToken(ctx, sa.ID, []byte("old"), &past)
	if got, err := s.TokenServiceAccount(ctx, []byte("tok")); err != nil || got.ID != sa.ID {
		t.Fatalf("TokenServiceAccount = %v, %v", got, err)
	}
	if _, err := s.TokenServiceAccount(ctx, []byte("old")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token err = %v", err)
	}
}

func TestRoleBindings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrganization(ctx, "acme", "ACME")
	p, _ := s.CreateProject(ctx, org.ID, "shop", "Shop")
	u, _ := s.CreateUser(ctx, "a@example.com", "A", "", false)

	if _, err := s.CreateRoleBinding(ctx, RoleBinding{OrgID: org.ID, Role: "org_admin", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRoleBinding(ctx, RoleBinding{OrgID: org.ID, ProjectID: p.ID, Role: "operator", OIDCGroup: "shop-ops"}); err != nil {
		t.Fatal(err)
	}
	// Exactly one subject is required.
	if _, err := s.CreateRoleBinding(ctx, RoleBinding{OrgID: org.ID, Role: "viewer"}); err == nil {
		t.Fatal("binding without subject was accepted")
	}

	direct, _ := s.BindingsForUser(ctx, u.ID, nil)
	withGroup, _ := s.BindingsForUser(ctx, u.ID, []string{"shop-ops"})
	if len(direct) != 1 || len(withGroup) != 2 {
		t.Fatalf("BindingsForUser: direct=%d withGroup=%d", len(direct), len(withGroup))
	}
	orgLevel, _ := s.ListRoleBindings(ctx, org.ID, "")
	projLevel, _ := s.ListRoleBindings(ctx, org.ID, p.ID)
	if len(orgLevel) != 1 || len(projLevel) != 1 || projLevel[0].OIDCGroup != "shop-ops" {
		t.Fatalf("ListRoleBindings: org=%v project=%v", orgLevel, projLevel)
	}

	if _, err := s.CreateCustomRole(ctx, org.ID, "key_custodian", []string{"key.export"}); err != nil {
		t.Fatal(err)
	}
	roles, err := s.ListCustomRoles(ctx, org.ID)
	if err != nil || len(roles) != 1 || roles[0].Permissions[0] != "key.export" {
		t.Fatalf("ListCustomRoles = %v, %v", roles, err)
	}
}

func TestAudit(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrganization(ctx, "acme", "ACME")
	for i := 0; i < 3; i++ {
		if err := s.InsertAudit(ctx, AuditEntry{OrgID: org.ID, ActorType: "user", ActorID: "u", Action: "project.create",
			ObjectType: "project", ObjectID: "p", After: []byte(`{"slug":"shop"}`), SourceIP: "127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	// Instance-level events have no organization.
	if err := s.InsertAudit(ctx, AuditEntry{ActorType: "user", ActorID: "u", Action: "user.create", ObjectType: "user", ObjectID: "x"}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListAudit(ctx, AuditQuery{OrgID: org.ID, Limit: 2})
	if err != nil || len(page) != 2 || page[0].ID < page[1].ID {
		t.Fatalf("ListAudit = %v, %v", page, err)
	}
	rest, _ := s.ListAudit(ctx, AuditQuery{OrgID: org.ID, BeforeID: page[1].ID})
	if len(rest) != 1 || string(rest[0].After) != `{"slug":"shop"}` {
		t.Fatalf("second page = %v", rest)
	}
}

// postgresSchema creates a schema for one test, drops it afterwards, and
// returns a DSN whose connections use it.
func postgresSchema(t *testing.T, dsn string) string {
	t.Helper()
	ctx := context.Background()
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "t_" + strings.ReplaceAll(NewID(), "-", "")
	if _, err := admin.db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}
