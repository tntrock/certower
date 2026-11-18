package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tntrock/certower/internal/policy"
)

// Organization is a tenant.
type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Project groups certificates, targets and agents inside an organization.
type Project struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) CreateOrganization(ctx context.Context, slug, name string) (*Organization, error) {
	o := &Organization{ID: newID(), Slug: slug, Name: name, CreatedAt: now()}
	_, err := s.exec(ctx, `INSERT INTO organizations (id, slug, name, created_at) VALUES (?, ?, ?, ?)`,
		o.ID, o.Slug, o.Name, o.CreatedAt)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	var o Organization
	err := s.queryRow(ctx, `SELECT id, slug, name, created_at FROM organizations WHERE slug = ?`, slug).
		Scan(&o.ID, &o.Slug, &o.Name, &o.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &o, nil
}

func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.query(ctx, `SELECT id, slug, name, created_at FROM organizations ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Slug, &o.Name, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) CreateProject(ctx context.Context, orgID, slug, name string) (*Project, error) {
	p := &Project{ID: newID(), OrgID: orgID, Slug: slug, Name: name, CreatedAt: now()}
	_, err := s.exec(ctx, `INSERT INTO projects (id, org_id, slug, name, created_at) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.OrgID, p.Slug, p.Name, p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) GetProjectBySlug(ctx context.Context, orgID, slug string) (*Project, error) {
	var p Project
	err := s.queryRow(ctx, `SELECT id, org_id, slug, name, created_at FROM projects WHERE org_id = ? AND slug = ?`, orgID, slug).
		Scan(&p.ID, &p.OrgID, &p.Slug, &p.Name, &p.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (s *Store) GetProject(ctx context.Context, id string) (*Project, error) {
	var p Project
	err := s.queryRow(ctx, `SELECT id, org_id, slug, name, created_at FROM projects WHERE id = ?`, id).
		Scan(&p.ID, &p.OrgID, &p.Slug, &p.Name, &p.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (s *Store) ListProjects(ctx context.Context, orgID string) ([]Project, error) {
	rows, err := s.query(ctx, `SELECT id, org_id, slug, name, created_at FROM projects WHERE org_id = ? ORDER BY slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Slug, &p.Name, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeleteProject(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM projects WHERE id = ?`, id)
}

// GetPolicy returns the project's policy, or the zero (unrestricted) policy
// if none is set.
func (s *Store) GetPolicy(ctx context.Context, projectID string) (policy.Policy, error) {
	var raw string
	err := s.queryRow(ctx, `SELECT rules FROM policies WHERE project_id = ?`, projectID).Scan(&raw)
	if err := mapErr(err); err == ErrNotFound {
		return policy.Policy{}, nil
	} else if err != nil {
		return policy.Policy{}, err
	}
	var p policy.Policy
	err = json.Unmarshal([]byte(raw), &p)
	return p, err
}

func (s *Store) PutPolicy(ctx context.Context, projectID string, p policy.Policy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.exec(ctx, `INSERT INTO policies (project_id, rules, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (project_id) DO UPDATE SET rules = excluded.rules, updated_at = excluded.updated_at`,
		projectID, string(raw), now())
	return err
}
