package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// User is a human account, local or from OIDC.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"displayName"`
	PasswordHash string    `json:"-"`
	IsSuperuser  bool      `json:"isSuperuser"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"createdAt"`
}

const userCols = `id, email, display_name, password_hash, is_superuser, disabled, created_at`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	var hash *string
	if err := sc.Scan(&u.ID, &u.Email, &u.DisplayName, &hash, &u.IsSuperuser, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	u.PasswordHash = str(hash)
	return &u, nil
}

func (s *Store) CreateUser(ctx context.Context, email, displayName, passwordHash string, superuser bool) (*User, error) {
	u := &User{ID: newID(), Email: email, DisplayName: displayName, PasswordHash: passwordHash, IsSuperuser: superuser, CreatedAt: now()}
	_, err := s.exec(ctx, `INSERT INTO users (id, email, display_name, password_hash, is_superuser, disabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.DisplayName, nullable(passwordHash), u.IsSuperuser, false, u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	return scanUser(s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, email))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.query(ctx, `SELECT `+userCols+` FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.queryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- sessions

// CreateSession stores a login. groups are the user's OIDC groups, if the
// login came through single sign-on.
func (s *Store) CreateSession(ctx context.Context, userID string, tokenHash []byte, expires time.Time, groups ...string) error {
	if groups == nil {
		groups = []string{}
	}
	g, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	_, err = s.exec(ctx, `INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, oidc_groups) VALUES (?, ?, ?, ?, ?, ?)`,
		newID(), userID, tokenHash, expires.UTC(), now(), string(g))
	return err
}

// SessionUser returns the active user owning an unexpired session.
func (s *Store) SessionUser(ctx context.Context, tokenHash []byte) (*User, error) {
	u, _, err := s.Session(ctx, tokenHash)
	return u, err
}

// Session returns the active user owning an unexpired session and the OIDC
// groups recorded with it.
func (s *Store) Session(ctx context.Context, tokenHash []byte) (*User, []string, error) {
	var groups string
	var u User
	var hash *string
	err := s.queryRow(ctx, `SELECT u.id, u.email, u.display_name, u.password_hash, u.is_superuser, u.disabled, u.created_at, s.oidc_groups
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND NOT u.disabled`, tokenHash, now()).
		Scan(&u.ID, &u.Email, &u.DisplayName, &hash, &u.IsSuperuser, &u.Disabled, &u.CreatedAt, &groups)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	u.PasswordHash = str(hash)
	var gs []string
	if err := json.Unmarshal([]byte(groups), &gs); err != nil {
		return nil, nil, fmt.Errorf("session groups: %w", err)
	}
	return &u, gs, nil
}

// ---------------------------------------------------------------- OIDC identities

// GetUserByOIDC finds the user linked to an identity provider subject.
func (s *Store) GetUserByOIDC(ctx context.Context, issuer, subject string) (*User, error) {
	return scanUser(s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, subject))
}

// OIDCSubject returns the identity a user is linked to, or "" if none.
func (s *Store) OIDCSubject(ctx context.Context, userID string) (issuer, subject string, err error) {
	var i, sub *string
	if err := s.queryRow(ctx, `SELECT oidc_issuer, oidc_subject FROM users WHERE id = ?`, userID).Scan(&i, &sub); err != nil {
		return "", "", mapErr(err)
	}
	return str(i), str(sub), nil
}

// LinkOIDC links a user to an identity provider subject.
func (s *Store) LinkOIDC(ctx context.Context, userID, issuer, subject string) error {
	return s.execOne(ctx, `UPDATE users SET oidc_issuer = ?, oidc_subject = ? WHERE id = ?`, issuer, subject, userID)
}

// CreateOIDCUser creates a user who signs in only through the identity
// provider.
func (s *Store) CreateOIDCUser(ctx context.Context, email, displayName, issuer, subject string) (*User, error) {
	u := &User{ID: newID(), Email: email, DisplayName: displayName, CreatedAt: now()}
	_, err := s.exec(ctx, `INSERT INTO users (id, email, display_name, oidc_issuer, oidc_subject, is_superuser, disabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.DisplayName, issuer, subject, false, false, u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now())
	return err
}

// ---------------------------------------------------------------- service accounts

// ServiceAccount is a machine identity scoped to one project.
type ServiceAccount struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"projectId"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) CreateServiceAccount(ctx context.Context, projectID, name string) (*ServiceAccount, error) {
	sa := &ServiceAccount{ID: newID(), ProjectID: projectID, Name: name, CreatedAt: now()}
	_, err := s.exec(ctx, `INSERT INTO service_accounts (id, project_id, name, created_at) VALUES (?, ?, ?, ?)`,
		sa.ID, sa.ProjectID, sa.Name, sa.CreatedAt)
	if err != nil {
		return nil, err
	}
	return sa, nil
}

func (s *Store) GetServiceAccountByName(ctx context.Context, projectID, name string) (*ServiceAccount, error) {
	var sa ServiceAccount
	err := s.queryRow(ctx, `SELECT id, project_id, name, created_at FROM service_accounts WHERE project_id = ? AND name = ?`, projectID, name).
		Scan(&sa.ID, &sa.ProjectID, &sa.Name, &sa.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &sa, nil
}

func (s *Store) ListServiceAccounts(ctx context.Context, projectID string) ([]ServiceAccount, error) {
	rows, err := s.query(ctx, `SELECT id, project_id, name, created_at FROM service_accounts WHERE project_id = ? ORDER BY name`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceAccount
	for rows.Next() {
		var sa ServiceAccount
		if err := rows.Scan(&sa.ID, &sa.ProjectID, &sa.Name, &sa.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

func (s *Store) DeleteServiceAccount(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM service_accounts WHERE id = ?`, id)
}

// APIToken is a bearer token for a service account. The token itself is
// shown once at creation and only its hash is stored.
type APIToken struct {
	ID               string     `json:"id"`
	ServiceAccountID string     `json:"serviceAccountId"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

func (s *Store) CreateAPIToken(ctx context.Context, serviceAccountID string, tokenHash []byte, expires *time.Time) (*APIToken, error) {
	t := &APIToken{ID: newID(), ServiceAccountID: serviceAccountID, ExpiresAt: expires, CreatedAt: now()}
	var exp any
	if expires != nil {
		exp = expires.UTC()
	}
	_, err := s.exec(ctx, `INSERT INTO api_tokens (id, service_account_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.ServiceAccountID, tokenHash, exp, t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// TokenServiceAccount returns the service account owning an unexpired token
// and records the use.
func (s *Store) TokenServiceAccount(ctx context.Context, tokenHash []byte) (*ServiceAccount, error) {
	var sa ServiceAccount
	var tokenID string
	t := now()
	err := s.queryRow(ctx, `SELECT t.id, sa.id, sa.project_id, sa.name, sa.created_at
		FROM api_tokens t JOIN service_accounts sa ON sa.id = t.service_account_id
		WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > ?)`, tokenHash, t).
		Scan(&tokenID, &sa.ID, &sa.ProjectID, &sa.Name, &sa.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	if _, err := s.exec(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, t, tokenID); err != nil {
		return nil, err
	}
	return &sa, nil
}

// ---------------------------------------------------------------- role bindings

// RoleBinding grants Role to exactly one of UserID, ServiceAccountID or
// OIDCGroup, in an organization or (with ProjectID) one of its projects.
type RoleBinding struct {
	ID               string    `json:"id"`
	OrgID            string    `json:"orgId"`
	ProjectID        string    `json:"projectId,omitempty"`
	Role             string    `json:"role"`
	UserID           string    `json:"userId,omitempty"`
	ServiceAccountID string    `json:"serviceAccountId,omitempty"`
	OIDCGroup        string    `json:"oidcGroup,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
}

const bindingCols = `id, org_id, project_id, role, user_id, service_account_id, oidc_group, created_at`

func scanBindings(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}) ([]RoleBinding, error) {
	defer rows.Close()
	var out []RoleBinding
	for rows.Next() {
		var b RoleBinding
		var project, user, sa, group *string
		if err := rows.Scan(&b.ID, &b.OrgID, &project, &b.Role, &user, &sa, &group, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.ProjectID, b.UserID, b.ServiceAccountID, b.OIDCGroup = str(project), str(user), str(sa), str(group)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) CreateRoleBinding(ctx context.Context, b RoleBinding) (*RoleBinding, error) {
	b.ID, b.CreatedAt = newID(), now()
	_, err := s.exec(ctx, `INSERT INTO role_bindings (`+bindingCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.OrgID, nullable(b.ProjectID), b.Role, nullable(b.UserID), nullable(b.ServiceAccountID), nullable(b.OIDCGroup), b.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListRoleBindings lists the bindings of an organization. With projectID
// set, only that project's bindings; otherwise only organization-level ones.
func (s *Store) ListRoleBindings(ctx context.Context, orgID, projectID string) ([]RoleBinding, error) {
	q := `SELECT ` + bindingCols + ` FROM role_bindings WHERE org_id = ? AND project_id IS NULL ORDER BY created_at`
	args := []any{orgID}
	if projectID != "" {
		q = `SELECT ` + bindingCols + ` FROM role_bindings WHERE org_id = ? AND project_id = ? ORDER BY created_at`
		args = append(args, projectID)
	}
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanBindings(rows)
}

// BindingsForUser returns every binding that applies to a user, directly or
// through one of the given OIDC groups.
func (s *Store) BindingsForUser(ctx context.Context, userID string, groups []string) ([]RoleBinding, error) {
	q := `SELECT ` + bindingCols + ` FROM role_bindings WHERE user_id = ?`
	args := []any{userID}
	for _, g := range groups {
		q += ` OR oidc_group = ?`
		args = append(args, g)
	}
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanBindings(rows)
}

func (s *Store) BindingsForServiceAccount(ctx context.Context, serviceAccountID string) ([]RoleBinding, error) {
	rows, err := s.query(ctx, `SELECT `+bindingCols+` FROM role_bindings WHERE service_account_id = ?`, serviceAccountID)
	if err != nil {
		return nil, err
	}
	return scanBindings(rows)
}

func (s *Store) GetRoleBinding(ctx context.Context, orgID, id string) (*RoleBinding, error) {
	rows, err := s.query(ctx, `SELECT `+bindingCols+` FROM role_bindings WHERE org_id = ? AND id = ?`, orgID, id)
	if err != nil {
		return nil, err
	}
	bs, err := scanBindings(rows)
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, ErrNotFound
	}
	return &bs[0], nil
}

func (s *Store) DeleteRoleBinding(ctx context.Context, orgID, id string) error {
	return s.execOne(ctx, `DELETE FROM role_bindings WHERE org_id = ? AND id = ?`, orgID, id)
}

// ---------------------------------------------------------------- custom roles

// CustomRole is an organization-defined role.
type CustomRole struct {
	ID          string   `json:"id"`
	OrgID       string   `json:"orgId"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func (s *Store) CreateCustomRole(ctx context.Context, orgID, name string, perms []string) (*CustomRole, error) {
	r := &CustomRole{ID: newID(), OrgID: orgID, Name: name, Permissions: perms}
	raw, err := json.Marshal(perms)
	if err != nil {
		return nil, err
	}
	if _, err := s.exec(ctx, `INSERT INTO custom_roles (id, org_id, name, permissions) VALUES (?, ?, ?, ?)`,
		r.ID, r.OrgID, r.Name, string(raw)); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) ListCustomRoles(ctx context.Context, orgID string) ([]CustomRole, error) {
	rows, err := s.query(ctx, `SELECT id, org_id, name, permissions FROM custom_roles WHERE org_id = ? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomRole
	for rows.Next() {
		var r CustomRole
		var raw string
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &r.Permissions); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
