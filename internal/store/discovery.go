package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// DiscoveryEndpoint is a TLS endpoint Certower scans.
type DiscoveryEndpoint struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"orgId"`
	ProjectID     string     `json:"projectId,omitempty"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	SNI           string     `json:"sni,omitempty"`
	LastScannedAt *time.Time `json:"lastScannedAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
}

const endpointCols = `id, org_id, project_id, host, port, sni, last_scanned_at, last_error`

func scanEndpoint(sc interface{ Scan(...any) error }) (*DiscoveryEndpoint, error) {
	var e DiscoveryEndpoint
	var project, lastErr *string
	var scanned sql.NullTime
	if err := sc.Scan(&e.ID, &e.OrgID, &project, &e.Host, &e.Port, &e.SNI, &scanned, &lastErr); err != nil {
		return nil, mapErr(err)
	}
	e.ProjectID, e.LastError = str(project), str(lastErr)
	if scanned.Valid {
		e.LastScannedAt = &scanned.Time
	}
	return &e, nil
}

func (s *Store) listEndpoints(ctx context.Context, query string, args ...any) ([]DiscoveryEndpoint, error) {
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DiscoveryEndpoint
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (s *Store) CreateEndpoint(ctx context.Context, e DiscoveryEndpoint) (*DiscoveryEndpoint, error) {
	e.ID = newID()
	_, err := s.exec(ctx, `INSERT INTO discovery_endpoints (`+endpointCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.OrgID, nullable(e.ProjectID), e.Host, e.Port, e.SNI, nil, nil)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) ListEndpoints(ctx context.Context, orgID string) ([]DiscoveryEndpoint, error) {
	return s.listEndpoints(ctx, `SELECT `+endpointCols+` FROM discovery_endpoints WHERE org_id = ? ORDER BY host, port`, orgID)
}

func (s *Store) GetEndpoint(ctx context.Context, orgID, id string) (*DiscoveryEndpoint, error) {
	return scanEndpoint(s.queryRow(ctx, `SELECT `+endpointCols+` FROM discovery_endpoints WHERE org_id = ? AND id = ?`, orgID, id))
}

func (s *Store) GetEndpointByID(ctx context.Context, id string) (*DiscoveryEndpoint, error) {
	return scanEndpoint(s.queryRow(ctx, `SELECT `+endpointCols+` FROM discovery_endpoints WHERE id = ?`, id))
}

func (s *Store) DeleteEndpoint(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM discovery_endpoints WHERE id = ?`, id)
}

// EndpointsDue returns endpoints never scanned or last scanned before the
// given time.
func (s *Store) EndpointsDue(ctx context.Context, scannedBefore time.Time, limit int) ([]DiscoveryEndpoint, error) {
	return s.listEndpoints(ctx, `SELECT `+endpointCols+` FROM discovery_endpoints
		WHERE last_scanned_at IS NULL OR last_scanned_at < ? ORDER BY last_scanned_at LIMIT ?`, scannedBefore.UTC(), limit)
}

// RecordScan stores when an endpoint was scanned and why it failed, if it did.
func (s *Store) RecordScan(ctx context.Context, id, errMsg string) error {
	return s.execOne(ctx, `UPDATE discovery_endpoints SET last_scanned_at = ?, last_error = ? WHERE id = ?`, now(), nullable(errMsg), id)
}

// DiscoveredCert is a certificate seen on an endpoint.
type DiscoveredCert struct {
	ID          string          `json:"id"`
	EndpointID  string          `json:"endpointId"`
	Fingerprint string          `json:"fingerprint"`
	Subject     string          `json:"subject"`
	Issuer      string          `json:"issuer"`
	Names       []string        `json:"names"`
	NotBefore   time.Time       `json:"notBefore"`
	NotAfter    time.Time       `json:"notAfter"`
	Findings    json.RawMessage `json:"findings"`
	// VersionID links to the managed certificate version with the same
	// fingerprint; empty means Certower does not manage this certificate.
	VersionID   string    `json:"versionId,omitempty"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
}

const discoveredCols = `id, endpoint_id, fingerprint, subject, issuer, names, not_before, not_after, findings, version_id, first_seen_at, last_seen_at`

// UpsertDiscovered records a sighting. isNew reports a certificate not seen
// on this endpoint before.
func (s *Store) UpsertDiscovered(ctx context.Context, d DiscoveredCert) (isNew bool, err error) {
	names, err := json.Marshal(d.Names)
	if err != nil {
		return false, err
	}
	if len(d.Findings) == 0 {
		d.Findings = json.RawMessage(`[]`)
	}
	t := now()
	err = s.InTx(ctx, func(tx *Store) error {
		var id string
		err := tx.queryRow(ctx, `SELECT id FROM discovered_certificates WHERE endpoint_id = ? AND fingerprint = ?`, d.EndpointID, d.Fingerprint).Scan(&id)
		if err := mapErr(err); errors.Is(err, ErrNotFound) {
			isNew = true
			_, err := tx.exec(ctx, `INSERT INTO discovered_certificates (`+discoveredCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				newID(), d.EndpointID, d.Fingerprint, d.Subject, d.Issuer, string(names), d.NotBefore.UTC(), d.NotAfter.UTC(),
				string(d.Findings), nullable(d.VersionID), t, t)
			return err
		} else if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE discovered_certificates SET findings = ?, version_id = ?, last_seen_at = ? WHERE id = ?`,
			string(d.Findings), nullable(d.VersionID), t, id)
		return err
	})
	return isNew, err
}

// LatestDiscovered returns the certificate most recently seen on an endpoint.
func (s *Store) LatestDiscovered(ctx context.Context, endpointID string) (*DiscoveredCert, error) {
	var d DiscoveredCert
	var names, findings string
	var version *string
	err := s.queryRow(ctx, `SELECT `+discoveredCols+` FROM discovered_certificates WHERE endpoint_id = ?
		ORDER BY last_seen_at DESC LIMIT 1`, endpointID).
		Scan(&d.ID, &d.EndpointID, &d.Fingerprint, &d.Subject, &d.Issuer, &names, &d.NotBefore, &d.NotAfter, &findings, &version, &d.FirstSeenAt, &d.LastSeenAt)
	if err != nil {
		return nil, mapErr(err)
	}
	d.Findings, d.VersionID = json.RawMessage(findings), str(version)
	return &d, json.Unmarshal([]byte(names), &d.Names)
}

// VersionByFingerprint finds a managed version by leaf fingerprint.
func (s *Store) VersionByFingerprint(ctx context.Context, fp string) (*CertificateVersion, error) {
	vs, err := s.listVersions(ctx, `fingerprint = ?`, fp)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, ErrNotFound
	}
	return &vs[0], nil
}

// ---------------------------------------------------------------- notifications

// LogNotification records that the event identified by key has been
// announced. first is false if it already was, so callers announce it once.
func (s *Store) LogNotification(ctx context.Context, key string) (first bool, err error) {
	_, err = s.exec(ctx, `INSERT INTO notification_log (dedupe_key, created_at) VALUES (?, ?)`, key, now())
	if errors.Is(err, ErrConflict) {
		return false, nil
	}
	return err == nil, err
}
