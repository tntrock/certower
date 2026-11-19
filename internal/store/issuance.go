package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// NewID returns a new row ID. Callers that must know an ID before the row
// exists (for example to bind it into encryption) use it with the Create
// functions that accept a preset ID.
func NewID() string { return newID() }

// ---------------------------------------------------------------- secrets

// SecretRow is an encrypted value; see internal/secrets.
type SecretRow struct {
	ID         string
	OrgID      string
	ProjectID  string
	Name       string
	KEKID      string
	WrappedDEK []byte
	Ciphertext []byte
}

func (s *Store) CreateSecret(ctx context.Context, r SecretRow) error {
	t := now()
	_, err := s.exec(ctx, `INSERT INTO secrets (id, org_id, project_id, name, kek_id, wrapped_dek, ciphertext, rotated_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.OrgID, nullable(r.ProjectID), r.Name, r.KEKID, r.WrappedDEK, r.Ciphertext, t, t)
	return err
}

func (s *Store) GetSecret(ctx context.Context, id string) (*SecretRow, error) {
	var r SecretRow
	var project *string
	err := s.queryRow(ctx, `SELECT id, org_id, project_id, name, kek_id, wrapped_dek, ciphertext FROM secrets WHERE id = ?`, id).
		Scan(&r.ID, &r.OrgID, &project, &r.Name, &r.KEKID, &r.WrappedDEK, &r.Ciphertext)
	if err != nil {
		return nil, mapErr(err)
	}
	r.ProjectID = str(project)
	return &r, nil
}

func (s *Store) DeleteSecret(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM secrets WHERE id = ?`, id)
}

// ---------------------------------------------------------------- plugin configs

// PluginConfig is a configured Issuer, DNS, Deployer or Notifier. Secret
// fields in Config hold {"$secret": "<id>"} references.
type PluginConfig struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"orgId"`
	ProjectID string          `json:"projectId,omitempty"`
	Kind      string          `json:"kind"`
	Plugin    string          `json:"plugin"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

const pluginConfigCols = `id, org_id, project_id, kind, plugin, name, config, created_at, updated_at`

func scanPluginConfig(sc interface{ Scan(...any) error }) (*PluginConfig, error) {
	var c PluginConfig
	var project *string
	var cfg string
	if err := sc.Scan(&c.ID, &c.OrgID, &project, &c.Kind, &c.Plugin, &c.Name, &cfg, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	c.ProjectID, c.Config = str(project), json.RawMessage(cfg)
	return &c, nil
}

// CreatePluginConfig inserts c, using c.ID if set.
func (s *Store) CreatePluginConfig(ctx context.Context, c PluginConfig) (*PluginConfig, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	c.CreatedAt = now()
	c.UpdatedAt = c.CreatedAt
	_, err := s.exec(ctx, `INSERT INTO plugin_configs (`+pluginConfigCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.OrgID, nullable(c.ProjectID), c.Kind, c.Plugin, c.Name, string(c.Config), c.CreatedAt, c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) GetPluginConfig(ctx context.Context, id string) (*PluginConfig, error) {
	return scanPluginConfig(s.queryRow(ctx, `SELECT `+pluginConfigCols+` FROM plugin_configs WHERE id = ?`, id))
}

// FindPluginConfig looks a config up by name as seen from a project: the
// project's own config wins over an organization-wide one of the same name.
func (s *Store) FindPluginConfig(ctx context.Context, orgID, projectID, kind, name string) (*PluginConfig, error) {
	if projectID != "" {
		c, err := scanPluginConfig(s.queryRow(ctx, `SELECT `+pluginConfigCols+` FROM plugin_configs
			WHERE org_id = ? AND project_id = ? AND kind = ? AND name = ?`, orgID, projectID, kind, name))
		if !errors.Is(err, ErrNotFound) {
			return c, err
		}
	}
	return scanPluginConfig(s.queryRow(ctx, `SELECT `+pluginConfigCols+` FROM plugin_configs
		WHERE org_id = ? AND project_id IS NULL AND kind = ? AND name = ?`, orgID, kind, name))
}

// ListPluginConfigs lists organization-wide configs, plus the project's own
// when projectID is set.
func (s *Store) ListPluginConfigs(ctx context.Context, orgID, projectID string) ([]PluginConfig, error) {
	q := `SELECT ` + pluginConfigCols + ` FROM plugin_configs WHERE org_id = ? AND (project_id IS NULL`
	args := []any{orgID}
	if projectID != "" {
		q += ` OR project_id = ?`
		args = append(args, projectID)
	}
	q += `) ORDER BY kind, name`
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PluginConfig
	for rows.Next() {
		c, err := scanPluginConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// DeletePluginConfig fails with ErrInvalidReference while certificates or
// targets still use the config.
func (s *Store) DeletePluginConfig(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM plugin_configs WHERE id = ?`, id)
}

// ---------------------------------------------------------------- certificates

// Certificate statuses.
const (
	CertPending = "pending" // never issued
	CertActive  = "active"  // has a valid version
	CertFailing = "failing" // the last attempt failed and will be retried
	CertInvalid = "invalid" // cannot be issued until someone fixes it
)

// Certificate is a managed certificate: the desired state renewals keep.
type Certificate struct {
	ID               string   `json:"id"`
	ProjectID        string   `json:"projectId"`
	Name             string   `json:"name"`
	Names            []string `json:"names"`
	KeyType          string   `json:"keyType"`
	IssuerConfigID   string   `json:"issuerConfigId"`
	DNSConfigID      string   `json:"dnsConfigId,omitempty"`
	Profile          string   `json:"profile,omitempty"`
	KeyLocation      string   `json:"keyLocation"`
	RenewBeforeRatio float64  `json:"renewBeforeRatio"`
	OwnerEmail       string   `json:"ownerEmail,omitempty"`
	Status           string   `json:"status"`
	LastError        string   `json:"lastError,omitempty"`
	// RenewRequestedAt is set by a manual renewal of an agent-held
	// certificate; the agent picks it up on its next sync.
	RenewRequestedAt *time.Time `json:"renewRequestedAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

const certCols = `id, project_id, name, names, key_type, issuer_config_id, dns_config_id, profile,
	key_location, renew_before_ratio, owner_email, status, last_error, renew_requested_at, created_at`

func scanCert(sc interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	var names string
	var dnsID, profile, owner, lastErr *string
	var renewReq sql.NullTime
	if err := sc.Scan(&c.ID, &c.ProjectID, &c.Name, &names, &c.KeyType, &c.IssuerConfigID, &dnsID, &profile,
		&c.KeyLocation, &c.RenewBeforeRatio, &owner, &c.Status, &lastErr, &renewReq, &c.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	if renewReq.Valid {
		c.RenewRequestedAt = &renewReq.Time
	}
	c.DNSConfigID, c.Profile, c.OwnerEmail, c.LastError = str(dnsID), str(profile), str(owner), str(lastErr)
	return &c, json.Unmarshal([]byte(names), &c.Names)
}

func (s *Store) CreateCertificate(ctx context.Context, c Certificate) (*Certificate, error) {
	c.ID, c.CreatedAt, c.Status = newID(), now(), CertPending
	if c.RenewBeforeRatio == 0 {
		c.RenewBeforeRatio = 1.0 / 3
	}
	names, err := json.Marshal(c.Names)
	if err != nil {
		return nil, err
	}
	_, err = s.exec(ctx, `INSERT INTO certificates (`+certCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.ProjectID, c.Name, string(names), c.KeyType, c.IssuerConfigID, nullable(c.DNSConfigID), nullable(c.Profile),
		c.KeyLocation, c.RenewBeforeRatio, nullable(c.OwnerEmail), c.Status, nil, nil, c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	return scanCert(s.queryRow(ctx, `SELECT `+certCols+` FROM certificates WHERE id = ?`, id))
}

func (s *Store) GetCertificateByName(ctx context.Context, projectID, name string) (*Certificate, error) {
	return scanCert(s.queryRow(ctx, `SELECT `+certCols+` FROM certificates WHERE project_id = ? AND name = ?`, projectID, name))
}

func (s *Store) ListCertificates(ctx context.Context, projectID string) ([]Certificate, error) {
	rows, err := s.query(ctx, `SELECT `+certCols+` FROM certificates WHERE project_id = ? ORDER BY name`, projectID)
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

func (s *Store) SetCertificateStatus(ctx context.Context, id, status, lastError string) error {
	return s.execOne(ctx, `UPDATE certificates SET status = ?, last_error = ? WHERE id = ?`, status, nullable(lastError), id)
}

func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM certificates WHERE id = ?`, id)
}

// CertificatesDue returns IDs of server-key certificates that need issuing:
// those with no unrevoked version whose renewal time is still ahead. Invalid
// certificates are skipped until someone fixes them. Agent-key certificates
// are renewed when their agent sends a CSR.
func (s *Store) CertificatesDue(ctx context.Context, at time.Time, limit int) ([]string, error) {
	rows, err := s.query(ctx, `SELECT c.id FROM certificates c
		WHERE c.status <> ? AND c.key_location = 'server' AND NOT EXISTS (
			SELECT 1 FROM certificate_versions v
			WHERE v.certificate_id = c.id AND v.revoked_at IS NULL AND v.renew_after > ?)
		ORDER BY c.created_at LIMIT ?`, CertInvalid, at.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---------------------------------------------------------------- versions

// CertificateVersion is one issued instance of a managed certificate.
type CertificateVersion struct {
	ID            string     `json:"id"`
	CertificateID string     `json:"certificateId"`
	Serial        string     `json:"serial"`
	Fingerprint   string     `json:"fingerprint"`
	ARICertID     string     `json:"ariCertId,omitempty"`
	NotBefore     time.Time  `json:"notBefore"`
	NotAfter      time.Time  `json:"notAfter"`
	RenewAfter    time.Time  `json:"renewAfter"`
	ChainPEM      string     `json:"-"`
	KeySecretID   string     `json:"-"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	RevokeReason  *int       `json:"revokeReason,omitempty"`
	ARICheckedAt  *time.Time `json:"ariCheckedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

const versionCols = `id, certificate_id, serial, fingerprint, ari_cert_id, not_before, not_after, renew_after,
	chain_pem, key_secret_id, revoked_at, revoke_reason, ari_checked_at, created_at`

func scanVersion(sc interface{ Scan(...any) error }) (*CertificateVersion, error) {
	var v CertificateVersion
	var ari, keyID *string
	var revoked, checked sql.NullTime
	var reason sql.NullInt64
	if err := sc.Scan(&v.ID, &v.CertificateID, &v.Serial, &v.Fingerprint, &ari, &v.NotBefore, &v.NotAfter, &v.RenewAfter,
		&v.ChainPEM, &keyID, &revoked, &reason, &checked, &v.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	v.ARICertID, v.KeySecretID = str(ari), str(keyID)
	if revoked.Valid {
		v.RevokedAt = &revoked.Time
	}
	if reason.Valid {
		r := int(reason.Int64)
		v.RevokeReason = &r
	}
	if checked.Valid {
		v.ARICheckedAt = &checked.Time
	}
	return &v, nil
}

// InsertCertificateVersion stores v, using v.ID if set.
func (s *Store) InsertCertificateVersion(ctx context.Context, v CertificateVersion) (*CertificateVersion, error) {
	if v.ID == "" {
		v.ID = newID()
	}
	v.CreatedAt = now()
	_, err := s.exec(ctx, `INSERT INTO certificate_versions (`+versionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.CertificateID, v.Serial, v.Fingerprint, nullable(v.ARICertID), v.NotBefore.UTC(), v.NotAfter.UTC(), v.RenewAfter.UTC(),
		v.ChainPEM, nullable(v.KeySecretID), nil, nil, nil, v.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) listVersions(ctx context.Context, where string, args ...any) ([]CertificateVersion, error) {
	rows, err := s.query(ctx, `SELECT `+versionCols+` FROM certificate_versions WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertificateVersion
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// ListVersions returns a certificate's versions, newest first.
func (s *Store) ListVersions(ctx context.Context, certID string) ([]CertificateVersion, error) {
	return s.listVersions(ctx, `certificate_id = ? ORDER BY created_at DESC`, certID)
}

// CurrentVersion returns the newest unrevoked version.
func (s *Store) CurrentVersion(ctx context.Context, certID string) (*CertificateVersion, error) {
	vs, err := s.listVersions(ctx, `certificate_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, certID)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, ErrNotFound
	}
	return &vs[0], nil
}

func (s *Store) GetVersion(ctx context.Context, certID, versionID string) (*CertificateVersion, error) {
	vs, err := s.listVersions(ctx, `certificate_id = ? AND id = ?`, certID, versionID)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, ErrNotFound
	}
	return &vs[0], nil
}

func (s *Store) MarkVersionRevoked(ctx context.Context, id string, reason int) error {
	return s.execOne(ctx, `UPDATE certificate_versions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL`,
		now(), reason, id)
}

// VersionsForARICheck returns unrevoked, unexpired versions with an ARI ID
// whose renewal window was last checked before the given time.
func (s *Store) VersionsForARICheck(ctx context.Context, checkedBefore time.Time, limit int) ([]CertificateVersion, error) {
	t := now()
	return s.listVersions(ctx, `revoked_at IS NULL AND ari_cert_id IS NOT NULL AND not_after > ?
		AND (ari_checked_at IS NULL OR ari_checked_at < ?) ORDER BY renew_after LIMIT ?`, t, checkedBefore.UTC(), limit)
}

func (s *Store) UpdateVersionRenewal(ctx context.Context, id string, renewAfter time.Time) error {
	return s.execOne(ctx, `UPDATE certificate_versions SET renew_after = ?, ari_checked_at = ? WHERE id = ?`, renewAfter.UTC(), now(), id)
}

// ---------------------------------------------------------------- jobs

// Job statuses.
const (
	JobQueued  = "queued"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// Job is a unit of background work.
type Job struct {
	ID        string          `json:"id"`
	ProjectID string          `json:"projectId,omitempty"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Status    string          `json:"status"`
	Attempts  int             `json:"attempts"`
	RunAfter  time.Time       `json:"runAfter"`
	LastError string          `json:"lastError,omitempty"`
	DedupeKey string          `json:"dedupeKey,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
}

const jobCols = `id, project_id, type, payload, status, attempts, run_after, last_error, dedupe_key, created_at`

func scanJob(sc interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	var project, lastErr, dedupe *string
	var payload string
	if err := sc.Scan(&j.ID, &project, &j.Type, &payload, &j.Status, &j.Attempts, &j.RunAfter, &lastErr, &dedupe, &j.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	j.ProjectID, j.LastError, j.DedupeKey, j.Payload = str(project), str(lastErr), str(dedupe), json.RawMessage(payload)
	return &j, nil
}

// EnqueueJob adds a job. If an open job with the same DedupeKey exists, it
// returns that job and created=false.
func (s *Store) EnqueueJob(ctx context.Context, j Job) (job *Job, created bool, err error) {
	j.ID, j.CreatedAt, j.Status, j.Attempts = newID(), now(), JobQueued, 0
	if j.RunAfter.IsZero() {
		j.RunAfter = j.CreatedAt
	}
	if len(j.Payload) == 0 {
		j.Payload = json.RawMessage(`{}`)
	}
	_, err = s.exec(ctx, `INSERT INTO jobs (`+jobCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.ID, nullable(j.ProjectID), j.Type, string(j.Payload), j.Status, j.Attempts, j.RunAfter.UTC(), nil, nullable(j.DedupeKey), j.CreatedAt)
	if errors.Is(err, ErrConflict) && j.DedupeKey != "" {
		existing, err := scanJob(s.queryRow(ctx, `SELECT `+jobCols+` FROM jobs
			WHERE dedupe_key = ? AND status IN ('queued', 'running', 'waiting_manual')`, j.DedupeKey))
		return existing, false, err
	}
	if err != nil {
		return nil, false, err
	}
	return &j, true, nil
}

// ClaimJob leases the next runnable job to worker for lease. Jobs whose
// lease expired (their worker died) are claimed again.
func (s *Store) ClaimJob(ctx context.Context, worker string, lease time.Duration) (*Job, error) {
	t := now()
	rows, err := s.query(ctx, `SELECT id FROM jobs
		WHERE (status = 'queued' AND run_after <= ?) OR (status = 'running' AND locked_until < ?)
		ORDER BY run_after LIMIT 5`, t, t)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		// Optimistic claim: only one worker's UPDATE matches.
		err := s.execOne(ctx, `UPDATE jobs SET status = 'running', locked_by = ?, locked_until = ?, attempts = attempts + 1
			WHERE id = ? AND ((status = 'queued' AND run_after <= ?) OR (status = 'running' AND locked_until < ?))`,
			worker, t.Add(lease), id, t, t)
		if errors.Is(err, ErrNotFound) {
			continue // another worker won
		}
		if err != nil {
			return nil, err
		}
		return scanJob(s.queryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
	}
	return nil, ErrNotFound
}

func (s *Store) CompleteJob(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE jobs SET status = 'done', locked_by = NULL, locked_until = NULL, last_error = NULL WHERE id = ?`, id)
}

// RetryJob puts a running job back in the queue.
func (s *Store) RetryJob(ctx context.Context, id string, runAfter time.Time, lastError string) error {
	return s.execOne(ctx, `UPDATE jobs SET status = 'queued', run_after = ?, last_error = ?, locked_by = NULL, locked_until = NULL WHERE id = ?`,
		runAfter.UTC(), lastError, id)
}

// FailJob stops a job for good.
func (s *Store) FailJob(ctx context.Context, id, lastError string) error {
	return s.execOne(ctx, `UPDATE jobs SET status = 'failed', last_error = ?, locked_by = NULL, locked_until = NULL WHERE id = ?`, lastError, id)
}

func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	return scanJob(s.queryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
}

// ListJobs returns a project's most recent jobs.
func (s *Store) ListJobs(ctx context.Context, projectID string, limit int) ([]Job, error) {
	rows, err := s.query(ctx, `SELECT `+jobCols+` FROM jobs WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// RequestRenewal marks an agent-held certificate for renewal on the
// agent's next sync.
func (s *Store) RequestRenewal(ctx context.Context, certID string) error {
	return s.execOne(ctx, `UPDATE certificates SET renew_requested_at = ? WHERE id = ?`, now(), certID)
}

// OpenJob returns the open job with the given de-duplication key.
func (s *Store) OpenJob(ctx context.Context, dedupeKey string) (*Job, error) {
	return scanJob(s.queryRow(ctx, `SELECT `+jobCols+` FROM jobs
		WHERE dedupe_key = ? AND status IN ('queued', 'running', 'waiting_manual')`, dedupeKey))
}

// ExpiringVersions returns the current (newest unrevoked) version of every
// certificate that expires before the given time.
func (s *Store) ExpiringVersions(ctx context.Context, before time.Time) ([]CertificateVersion, error) {
	return s.listVersions(ctx, `revoked_at IS NULL AND not_after < ? AND NOT EXISTS (
		SELECT 1 FROM certificate_versions n WHERE n.certificate_id = certificate_versions.certificate_id
		AND n.revoked_at IS NULL AND n.created_at > certificate_versions.created_at)`, before.UTC())
}
