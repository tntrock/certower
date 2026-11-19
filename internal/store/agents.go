package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------- agents

// Agent is a certower-agent process on a host. It is created as an
// invitation holding a one-time enrollment token, and becomes enrolled when
// the agent redeems the token.
type Agent struct {
	ID              string     `json:"id"`
	ProjectID       string     `json:"projectId"`
	Name            string     `json:"name"`
	Hostname        string     `json:"hostname,omitempty"`
	OS              string     `json:"os,omitempty"`
	Version         string     `json:"version,omitempty"`
	Enrolled        bool       `json:"enrolled"`
	EnrollExpiresAt *time.Time `json:"enrollExpiresAt,omitempty"`
	LastSeenAt      *time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}

const agentCols = `id, project_id, name, hostname, os, version, client_cert_fp, enroll_expires_at, last_seen_at, created_at`

func scanAgent(sc interface{ Scan(...any) error }) (*Agent, error) {
	var a Agent
	var fp *string
	var expires, seen sql.NullTime
	if err := sc.Scan(&a.ID, &a.ProjectID, &a.Name, &a.Hostname, &a.OS, &a.Version, &fp, &expires, &seen, &a.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	a.Enrolled = fp != nil
	if expires.Valid && !a.Enrolled {
		a.EnrollExpiresAt = &expires.Time
	}
	if seen.Valid {
		a.LastSeenAt = &seen.Time
	}
	return &a, nil
}

// CreateAgentInvitation creates an agent awaiting enrollment.
func (s *Store) CreateAgentInvitation(ctx context.Context, projectID, name string, tokenHash []byte, expires time.Time) (*Agent, error) {
	a := &Agent{ID: newID(), ProjectID: projectID, Name: name, EnrollExpiresAt: &expires, CreatedAt: now()}
	_, err := s.exec(ctx, `INSERT INTO agents (id, project_id, name, hostname, os, version, enroll_token_hash, enroll_expires_at, created_at)
		VALUES (?, ?, ?, '', '', '', ?, ?, ?)`, a.ID, projectID, name, tokenHash, expires.UTC(), a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// EnrollAgent redeems an unexpired enrollment token, binding the agent to
// the fingerprint of its new client certificate. The token works once.
func (s *Store) EnrollAgent(ctx context.Context, tokenHash []byte, certFP, hostname, os, version string) (*Agent, error) {
	var a *Agent
	err := s.InTx(ctx, func(tx *Store) error {
		var err error
		a, err = scanAgent(tx.queryRow(ctx, `SELECT `+agentCols+` FROM agents
			WHERE enroll_token_hash = ? AND enroll_expires_at > ?`, tokenHash, now()))
		if err != nil {
			return err
		}
		return tx.execOne(ctx, `UPDATE agents SET enroll_token_hash = NULL, enroll_expires_at = NULL,
			client_cert_fp = ?, hostname = ?, os = ?, version = ?, last_seen_at = ?
			WHERE id = ? AND enroll_token_hash = ?`, certFP, hostname, os, version, now(), a.ID, tokenHash)
	})
	if err != nil {
		return nil, err
	}
	a.Enrolled, a.Hostname, a.OS, a.Version, a.EnrollExpiresAt = true, hostname, os, version, nil
	return a, nil
}

// AgentByCertificate finds the agent presenting a client certificate.
// next reports that it is the certificate issued by the last identity
// renewal, which the agent has now started using.
func (s *Store) AgentByCertificate(ctx context.Context, certFP string) (a *Agent, next bool, err error) {
	var nextFP *string
	row := s.queryRow(ctx, `SELECT `+agentCols+`, client_cert_fp_next FROM agents
		WHERE client_cert_fp = ? OR client_cert_fp_next = ?`, certFP, certFP)
	var ag Agent
	var fp *string
	var expires, seen sql.NullTime
	if err := row.Scan(&ag.ID, &ag.ProjectID, &ag.Name, &ag.Hostname, &ag.OS, &ag.Version, &fp, &expires, &seen, &ag.CreatedAt, &nextFP); err != nil {
		return nil, false, mapErr(err)
	}
	ag.Enrolled = true
	if seen.Valid {
		ag.LastSeenAt = &seen.Time
	}
	return &ag, nextFP != nil && *nextFP == certFP, nil
}

// SetAgentNextCertificate records a renewed client certificate. Both the
// current and the next certificate work until PromoteAgentCertificate.
func (s *Store) SetAgentNextCertificate(ctx context.Context, agentID, certFP string) error {
	return s.execOne(ctx, `UPDATE agents SET client_cert_fp_next = ? WHERE id = ?`, certFP, agentID)
}

// PromoteAgentCertificate retires the old client certificate once the
// agent uses the new one.
func (s *Store) PromoteAgentCertificate(ctx context.Context, agentID string) error {
	return s.execOne(ctx, `UPDATE agents SET client_cert_fp = client_cert_fp_next, client_cert_fp_next = NULL
		WHERE id = ? AND client_cert_fp_next IS NOT NULL`, agentID)
}

// TouchAgent records that an agent checked in.
func (s *Store) TouchAgent(ctx context.Context, agentID, hostname, os, version string) error {
	return s.execOne(ctx, `UPDATE agents SET hostname = ?, os = ?, version = ?, last_seen_at = ? WHERE id = ?`,
		hostname, os, version, now(), agentID)
}

func (s *Store) ListAgents(ctx context.Context, projectID string) ([]Agent, error) {
	rows, err := s.query(ctx, `SELECT `+agentCols+` FROM agents WHERE project_id = ? ORDER BY name`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) GetAgentByName(ctx context.Context, projectID, name string) (*Agent, error) {
	return scanAgent(s.queryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE project_id = ? AND name = ?`, projectID, name))
}

// DeleteAgent removes an agent; its client certificate stops working and
// its targets are removed.
func (s *Store) DeleteAgent(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM agents WHERE id = ?`, id)
}

// ---------------------------------------------------------------- targets

// Target is a place an agent installs certificates, such as one nginx
// server. Settings are deployer-specific.
type Target struct {
	ID        string          `json:"id"`
	ProjectID string          `json:"projectId"`
	Name      string          `json:"name"`
	AgentID   string          `json:"agentId"`
	Deployer  string          `json:"deployer"`
	Settings  json.RawMessage `json:"settings"`
	CreatedAt time.Time       `json:"createdAt"`
}

const targetCols = `id, project_id, name, agent_id, deployer, settings, created_at`

func scanTarget(sc interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var settings string
	if err := sc.Scan(&t.ID, &t.ProjectID, &t.Name, &t.AgentID, &t.Deployer, &settings, &t.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	t.Settings = json.RawMessage(settings)
	return &t, nil
}

func (s *Store) listTargets(ctx context.Context, query string, args ...any) ([]Target, error) {
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) CreateTarget(ctx context.Context, t Target) (*Target, error) {
	t.ID, t.CreatedAt = newID(), now()
	if len(t.Settings) == 0 {
		t.Settings = json.RawMessage(`{}`)
	}
	_, err := s.exec(ctx, `INSERT INTO targets (`+targetCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.ProjectID, t.Name, t.AgentID, t.Deployer, string(t.Settings), t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListTargets(ctx context.Context, projectID string) ([]Target, error) {
	return s.listTargets(ctx, `SELECT `+targetCols+` FROM targets WHERE project_id = ? ORDER BY name`, projectID)
}

func (s *Store) GetTargetByName(ctx context.Context, projectID, name string) (*Target, error) {
	return scanTarget(s.queryRow(ctx, `SELECT `+targetCols+` FROM targets WHERE project_id = ? AND name = ?`, projectID, name))
}

func (s *Store) DeleteTarget(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM targets WHERE id = ?`, id)
}

// TargetsForCertificate lists the targets a certificate is deployed to.
func (s *Store) TargetsForCertificate(ctx context.Context, certID string) ([]Target, error) {
	return s.listTargets(ctx, `SELECT t.id, t.project_id, t.name, t.agent_id, t.deployer, t.settings, t.created_at
		FROM targets t JOIN certificate_targets ct ON ct.target_id = t.id
		WHERE ct.certificate_id = ? ORDER BY t.name`, certID)
}

func (s *Store) AttachTarget(ctx context.Context, certID, targetID string) error {
	_, err := s.exec(ctx, `INSERT INTO certificate_targets (certificate_id, target_id) VALUES (?, ?)`, certID, targetID)
	return err
}

func (s *Store) DetachTarget(ctx context.Context, certID, targetID string) error {
	return s.execOne(ctx, `DELETE FROM certificate_targets WHERE certificate_id = ? AND target_id = ?`, certID, targetID)
}

// CertificatesForAgent lists certificates with at least one target on the
// agent.
func (s *Store) CertificatesForAgent(ctx context.Context, agentID string) ([]Certificate, error) {
	rows, err := s.query(ctx, `SELECT `+certCols+` FROM certificates WHERE id IN (
		SELECT ct.certificate_id FROM certificate_targets ct JOIN targets t ON t.id = ct.target_id
		WHERE t.agent_id = ?) ORDER BY name`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- deployments

// Deployment is the latest outcome of installing a version on a target.
type Deployment struct {
	ID         string    `json:"id"`
	VersionID  string    `json:"versionId"`
	TargetID   string    `json:"targetId"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	FinishedAt time.Time `json:"finishedAt"`
}

// RecordDeployment stores or replaces the outcome for a version on a target.
func (s *Store) RecordDeployment(ctx context.Context, d Deployment) error {
	_, err := s.exec(ctx, `INSERT INTO deployments (id, version_id, target_id, status, message, finished_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (version_id, target_id) DO UPDATE SET status = excluded.status, message = excluded.message, finished_at = excluded.finished_at`,
		newID(), d.VersionID, d.TargetID, d.Status, nullable(d.Message), now())
	return err
}

// DeploymentsForCertificate returns every deployment of every version of a
// certificate, newest first.
func (s *Store) DeploymentsForCertificate(ctx context.Context, certID string) ([]Deployment, error) {
	rows, err := s.query(ctx, `SELECT d.id, d.version_id, d.target_id, d.status, d.message, d.finished_at
		FROM deployments d JOIN certificate_versions v ON v.id = d.version_id
		WHERE v.certificate_id = ? ORDER BY d.finished_at DESC`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Deployment
	for rows.Next() {
		var d Deployment
		var msg *string
		if err := rows.Scan(&d.ID, &d.VersionID, &d.TargetID, &d.Status, &msg, &d.FinishedAt); err != nil {
			return nil, err
		}
		d.Message = str(msg)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- server keys

// ServerKey is an instance-wide key pair, such as the agent CA. The private
// key is sealed with the KEK by the caller.
type ServerKey struct {
	Name       string
	CertPEM    string
	KEKID      string
	WrappedDEK []byte
	Ciphertext []byte
}

func (s *Store) GetServerKey(ctx context.Context, name string) (*ServerKey, error) {
	var k ServerKey
	err := s.queryRow(ctx, `SELECT name, cert_pem, kek_id, wrapped_dek, ciphertext FROM server_keys WHERE name = ?`, name).
		Scan(&k.Name, &k.CertPEM, &k.KEKID, &k.WrappedDEK, &k.Ciphertext)
	if err != nil {
		return nil, mapErr(err)
	}
	return &k, nil
}

// CreateServerKey fails with ErrConflict if the name exists, so concurrent
// servers creating the same key agree on one.
func (s *Store) CreateServerKey(ctx context.Context, k ServerKey) error {
	_, err := s.exec(ctx, `INSERT INTO server_keys (name, cert_pem, kek_id, wrapped_dek, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.Name, k.CertPEM, k.KEKID, k.WrappedDEK, k.Ciphertext, now())
	return err
}
