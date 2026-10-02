package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// Host is one row of the heartbeat registry.
type Host struct {
	Env      string             `json:"env"`
	Host     string             `json:"host"`
	IP       string             `json:"ip"`
	Role     string             `json:"role"`
	Status   string             `json:"status"` // up | missing | unknown
	LastSeen *time.Time         `json:"last_seen"`
	Known    bool               `json:"known"`
	Last     map[string]float64 `json:"last"` // last metric values
}

// SaveHosts upserts the registry rows.
func (s *Store) SaveHosts(ctx context.Context, hosts []Host) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, h := range hosts {
		var seen any
		if h.LastSeen != nil {
			seen = ms(*h.LastSeen)
		}
		last, _ := json.Marshal(h.Last)
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosts (env, host, ip, role, status, last_seen, known, last) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (env, host) DO UPDATE SET ip = excluded.ip, role = excluded.role, status = excluded.status,
			last_seen = excluded.last_seen, known = excluded.known, last = excluded.last`,
			h.Env, h.Host, h.IP, h.Role, h.Status, seen, h.Known, string(last)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Hosts returns the registry rows of the given environments (all if envs is nil).
func (s *Store) Hosts(ctx context.Context, envs []string) ([]Host, error) {
	q, args := "SELECT env, host, ip, role, status, last_seen, known, last FROM hosts", []any{}
	if envs != nil {
		q, args = q+" WHERE env IN "+placeholders(len(envs)), anys(envs)
	}
	rows, err := s.r.QueryContext(ctx, q+" ORDER BY env, host", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Host{}
	for rows.Next() {
		var h Host
		var seen sql.NullInt64
		var last sql.NullString
		if err := rows.Scan(&h.Env, &h.Host, &h.IP, &h.Role, &h.Status, &seen, &h.Known, &last); err != nil {
			return nil, err
		}
		if seen.Valid {
			t := time.UnixMilli(seen.Int64).UTC()
			h.LastSeen = &t
		}
		if last.Valid {
			_ = json.Unmarshal([]byte(last.String), &h.Last)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	b := []byte("(")
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(append(b, ')'))
}

func anys(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
