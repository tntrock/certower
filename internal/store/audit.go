package store

import (
	"context"
	"encoding/json"
	"time"
)

// AuditEntry records one mutating action.
type AuditEntry struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	OrgID      string          `json:"orgId,omitempty"`
	ProjectID  string          `json:"projectId,omitempty"`
	ActorType  string          `json:"actorType"`
	ActorID    string          `json:"actorId"`
	Action     string          `json:"action"`
	ObjectType string          `json:"objectType"`
	ObjectID   string          `json:"objectId"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	SourceIP   string          `json:"sourceIp,omitempty"`
}

func rawOrNil(r json.RawMessage) any {
	if len(r) == 0 {
		return nil
	}
	return string(r)
}

func (s *Store) InsertAudit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = now()
	}
	_, err := s.exec(ctx, `INSERT INTO audit_log
		(at, org_id, project_id, actor_type, actor_id, action, object_type, object_id, before, after, source_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At, nullable(e.OrgID), nullable(e.ProjectID), e.ActorType, e.ActorID, e.Action,
		e.ObjectType, e.ObjectID, rawOrNil(e.Before), rawOrNil(e.After), nullable(e.SourceIP))
	return err
}

// AuditQuery filters ListAudit. BeforeID pages backwards from an entry.
type AuditQuery struct {
	OrgID     string
	ProjectID string
	BeforeID  int64
	Limit     int
}

// ListAudit returns entries newest first.
func (s *Store) ListAudit(ctx context.Context, q AuditQuery) ([]AuditEntry, error) {
	sqlq := `SELECT id, at, org_id, project_id, actor_type, actor_id, action, object_type, object_id, before, after, source_ip
		FROM audit_log WHERE org_id = ?`
	args := []any{q.OrgID}
	if q.ProjectID != "" {
		sqlq += ` AND project_id = ?`
		args = append(args, q.ProjectID)
	}
	if q.BeforeID > 0 {
		sqlq += ` AND id < ?`
		args = append(args, q.BeforeID)
	}
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	sqlq += ` ORDER BY id DESC LIMIT ?`
	args = append(args, q.Limit)

	rows, err := s.query(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var org, project, before, after, ip *string
		if err := rows.Scan(&e.ID, &e.At, &org, &project, &e.ActorType, &e.ActorID, &e.Action,
			&e.ObjectType, &e.ObjectID, &before, &after, &ip); err != nil {
			return nil, err
		}
		e.OrgID, e.ProjectID, e.SourceIP = str(org), str(project), str(ip)
		if before != nil {
			e.Before = json.RawMessage(*before)
		}
		if after != nil {
			e.After = json.RawMessage(*after)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
