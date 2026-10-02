package store

import (
	"context"
	"database/sql"
	"time"
)

// Message is one pending notification.
type Message struct {
	ID       int64
	Route    string
	Text     string
	Incident int64
	Attempts int
}

// Enqueue adds a message for a route.
func (s *Store) Enqueue(ctx context.Context, route, text string, incident int64, now time.Time) error {
	var inc any
	if incident > 0 {
		inc = incident
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO outbox (created, route, text, incident, next_try) VALUES (?, ?, ?, ?, ?)`,
		ms(now), route, text, inc, ms(now))
	return err
}

// Due returns messages whose next try is due, oldest first.
func (s *Store) Due(ctx context.Context, now time.Time, limit int) ([]Message, error) {
	rows, err := s.w.QueryContext(ctx, `SELECT id, route, text, incident, attempts FROM outbox
		WHERE sent IS NULL AND next_try <= ? ORDER BY id LIMIT ?`, ms(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		var inc sql.NullInt64
		if err := rows.Scan(&m.ID, &m.Route, &m.Text, &inc, &m.Attempts); err != nil {
			return nil, err
		}
		m.Incident = inc.Int64
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkSent marks a message delivered.
func (s *Store) MarkSent(ctx context.Context, id int64, now time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE outbox SET sent = ?, error = '' WHERE id = ?`, ms(now), id)
	return err
}

// MarkFailed schedules the next try.
func (s *Store) MarkFailed(ctx context.Context, id int64, next time.Time, reason string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE outbox SET attempts = attempts + 1, next_try = ?, error = ? WHERE id = ?`, ms(next), reason, id)
	return err
}

// PendingCount returns the number of undelivered messages.
func (s *Store) PendingCount(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE sent IS NULL`).Scan(&n)
	return n, err
}
