package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Incident statuses.
const (
	StatusOpen     = "open"
	StatusResolved = "resolved"
)

// Incident is one alarm from opening to resolution.
type Incident struct {
	ID       int64      `json:"id"`
	Key      string     `json:"key"`
	Rule     string     `json:"rule"`
	Env      string     `json:"env"`
	Host     string     `json:"host"`
	Severity string     `json:"severity"`
	Status   string     `json:"status"`
	Opened   time.Time  `json:"opened"`
	Resolved *time.Time `json:"resolved"`
	Text     string     `json:"text"`
	AIText   string     `json:"ai_text"`
}

// OpenIncident inserts an open incident; ok=false if one with this key is already open.
func (s *Store) OpenIncident(ctx context.Context, in Incident) (int64, bool, error) {
	res, err := s.w.ExecContext(ctx, `INSERT INTO incidents (key, rule, env, host, severity, status, opened, text) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
		ON CONFLICT (key) WHERE status = 'open' DO NOTHING`, in.Key, in.Rule, in.Env, in.Host, in.Severity, ms(in.Opened), in.Text)
	if err != nil {
		return 0, false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, false, nil
	}
	id, err := res.LastInsertId()
	return id, true, err
}

// ResolveIncident resolves the open incident with this key; returns it (ok=false if none was open).
func (s *Store) ResolveIncident(ctx context.Context, key string, at time.Time) (Incident, bool, error) {
	in, err := s.openByKey(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, err
	}
	if _, err := s.w.ExecContext(ctx, `UPDATE incidents SET status = 'resolved', resolved = ? WHERE id = ?`, ms(at), in.ID); err != nil {
		return Incident{}, false, err
	}
	in.Status = StatusResolved
	t := at.UTC()
	in.Resolved = &t
	return in, true, nil
}

// SetAIText stores the AI explanation of an incident.
func (s *Store) SetAIText(ctx context.Context, id int64, text string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE incidents SET ai_text = ? WHERE id = ?`, text, id)
	return err
}

// OpenIncidentKeys returns the keys of all open incidents (state after a restart).
func (s *Store) OpenIncidentKeys(ctx context.Context) (map[string]Incident, error) {
	list, err := s.Incidents(ctx, IncidentFilter{Status: StatusOpen, Limit: 10000})
	if err != nil {
		return nil, err
	}
	out := make(map[string]Incident, len(list))
	for _, in := range list {
		out[in.Key] = in
	}
	return out, nil
}

func (s *Store) openByKey(ctx context.Context, key string) (Incident, error) {
	row := s.w.QueryRowContext(ctx, `SELECT `+incidentCols+` FROM incidents WHERE key = ? AND status = 'open'`, key)
	return scanIncident(row)
}

// IncidentFilter selects incidents.
type IncidentFilter struct {
	Envs   []string
	Status string
	Since  time.Time
	Limit  int
}

const incidentCols = `id, key, rule, env, host, severity, status, opened, resolved, text, ai_text`

// Incidents lists incidents, newest first.
func (s *Store) Incidents(ctx context.Context, f IncidentFilter) ([]Incident, error) {
	q, args := `SELECT `+incidentCols+` FROM incidents WHERE opened >= ?`, []any{ms(f.Since)}
	if f.Status != "" {
		q, args = q+` AND status = ?`, append(args, f.Status)
	}
	if f.Envs != nil {
		q, args = q+` AND env IN `+placeholders(len(f.Envs)), append(args, anys(f.Envs)...)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY opened DESC, id DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanIncident(sc scanner) (Incident, error) {
	var in Incident
	var opened int64
	var resolved sql.NullInt64
	if err := sc.Scan(&in.ID, &in.Key, &in.Rule, &in.Env, &in.Host, &in.Severity, &in.Status, &opened, &resolved, &in.Text, &in.AIText); err != nil {
		return in, err
	}
	in.Opened = time.UnixMilli(opened).UTC()
	if resolved.Valid {
		t := time.UnixMilli(resolved.Int64).UTC()
		in.Resolved = &t
	}
	return in, nil
}
