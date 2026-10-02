package store

import (
	"context"
	"strings"
	"time"
)

// Notified returns the routes an incident was announced to, with the time of the last message.
func (s *Store) Notified(ctx context.Context, incident int64) (map[string]time.Time, error) {
	rows, err := s.w.QueryContext(ctx, `SELECT route, at FROM notified WHERE incident = ?`, incident)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var r string
		var at int64
		if err := rows.Scan(&r, &at); err != nil {
			return nil, err
		}
		out[r] = time.UnixMilli(at).UTC()
	}
	return out, rows.Err()
}

// MarkNotified records that an incident was announced (or reminded) on a route.
func (s *Store) MarkNotified(ctx context.Context, incident int64, route string, at time.Time) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO notified (incident, route, at) VALUES (?, ?, ?)
		ON CONFLICT (incident, route) DO UPDATE SET at = excluded.at`, incident, route, ms(at))
	return err
}

// Silence mutes notifications of matching incidents between Starts and Ends.
type Silence struct {
	ID        int64     `json:"id"`
	Env       string    `json:"env"`
	Host      string    `json:"host"`
	Role      string    `json:"role"`
	Service   string    `json:"service"`
	Rule      string    `json:"rule"`
	Severity  []string  `json:"severity"`
	Starts    time.Time `json:"starts"`
	Ends      time.Time `json:"ends"`
	Comment   string    `json:"comment"`
	CreatedBy string    `json:"created_by"`
	Created   time.Time `json:"created"`
}

// AddSilence stores a silence and returns its id.
func (s *Store) AddSilence(ctx context.Context, x Silence) (int64, error) {
	res, err := s.w.ExecContext(ctx, `INSERT INTO silences (env, host, role, service, rule, severity, starts, ends, comment, created_by, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, x.Env, x.Host, x.Role, x.Service, x.Rule, strings.Join(x.Severity, ","),
		ms(x.Starts), ms(x.Ends), x.Comment, x.CreatedBy, ms(x.Created))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EndSilence ends a silence now; ok=false if it does not exist.
func (s *Store) EndSilence(ctx context.Context, id int64, now time.Time) (bool, error) {
	res, err := s.w.ExecContext(ctx, `UPDATE silences SET ends = min(ends, ?) WHERE id = ?`, ms(now), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// GetSilence returns one silence.
func (s *Store) GetSilence(ctx context.Context, id int64) (Silence, bool, error) {
	list, err := s.silences(ctx, `WHERE id = ?`, id)
	if err != nil || len(list) == 0 {
		return Silence{}, false, err
	}
	return list[0], true, nil
}

// Silences returns silences that have not ended at t, newest first.
func (s *Store) Silences(ctx context.Context, t time.Time) ([]Silence, error) {
	return s.silences(ctx, `WHERE ends > ? ORDER BY id DESC`, ms(t))
}

func (s *Store) silences(ctx context.Context, where string, args ...any) ([]Silence, error) {
	rows, err := s.w.QueryContext(ctx, `SELECT id, env, host, role, service, rule, severity, starts, ends, comment, created_by, created FROM silences `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Silence{}
	for rows.Next() {
		var x Silence
		var sev string
		var st, en, cr int64
		if err := rows.Scan(&x.ID, &x.Env, &x.Host, &x.Role, &x.Service, &x.Rule, &sev, &st, &en, &x.Comment, &x.CreatedBy, &cr); err != nil {
			return nil, err
		}
		if sev != "" {
			x.Severity = strings.Split(sev, ",")
		}
		x.Starts, x.Ends, x.Created = time.UnixMilli(st).UTC(), time.UnixMilli(en).UTC(), time.UnixMilli(cr).UTC()
		out = append(out, x)
	}
	return out, rows.Err()
}
