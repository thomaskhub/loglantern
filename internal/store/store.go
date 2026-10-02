// Package store keeps loglantern's data in one SQLite file (pure Go driver, WAL). One writer
// connection takes batches; reads (API, window rebuild) use a separate pool.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/thomkin/loglantern/internal/record"
)

const schemaVersion = 1

var schema = []string{
	`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, env TEXT NOT NULL, host TEXT NOT NULL,
		service TEXT NOT NULL, level INTEGER NOT NULL, msg TEXT NOT NULL, fields TEXT)`,
	`CREATE INDEX IF NOT EXISTS logs_ts ON logs (ts)`,
	`CREATE INDEX IF NOT EXISTS logs_env_host_ts ON logs (env, host, ts)`,
	`CREATE TABLE IF NOT EXISTS metrics (
		minute INTEGER NOT NULL, env TEXT NOT NULL, host TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL,
		PRIMARY KEY (env, host, name, minute)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS metrics_minute ON metrics (minute)`,
	`CREATE TABLE IF NOT EXISTS texts (
		minute INTEGER NOT NULL, env TEXT NOT NULL, host TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
		PRIMARY KEY (env, host, name, minute)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS texts_minute ON texts (minute)`,
	`CREATE TABLE IF NOT EXISTS counters (
		hour INTEGER NOT NULL, env TEXT NOT NULL, host TEXT NOT NULL, service TEXT NOT NULL, level INTEGER NOT NULL,
		n INTEGER NOT NULL, PRIMARY KEY (env, host, service, level, hour)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS counters_hour ON counters (hour)`,
	`CREATE TABLE IF NOT EXISTS hosts (
		env TEXT NOT NULL, host TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL, last_seen INTEGER, known INTEGER NOT NULL DEFAULT 0, last TEXT,
		PRIMARY KEY (env, host)) WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS incidents (
		id INTEGER PRIMARY KEY, key TEXT NOT NULL, rule TEXT NOT NULL, env TEXT NOT NULL, host TEXT NOT NULL,
		severity TEXT NOT NULL, status TEXT NOT NULL, opened INTEGER NOT NULL, resolved INTEGER,
		text TEXT NOT NULL, ai_text TEXT NOT NULL DEFAULT '')`,
	`CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_key ON incidents (key) WHERE status = 'open'`,
	`CREATE INDEX IF NOT EXISTS incidents_opened ON incidents (opened)`,
	`CREATE TABLE IF NOT EXISTS outbox (
		id INTEGER PRIMARY KEY, created INTEGER NOT NULL, route TEXT NOT NULL, text TEXT NOT NULL,
		incident INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL, sent INTEGER, error TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS outbox_pending ON outbox (next_try) WHERE sent IS NULL`,
}

// Store is the database.
type Store struct {
	w *sql.DB // single writer
	r *sql.DB // readers
}

// Open opens (and creates) the database file.
func Open(path string, cacheMB int) (*Store, error) {
	dsn := func(ro bool) string {
		q := url.Values{}
		for _, p := range []string{"journal_mode(WAL)", "busy_timeout(10000)", "synchronous(NORMAL)", "foreign_keys(ON)",
			fmt.Sprintf("cache_size(-%d)", cacheMB*1024)} {
			q.Add("_pragma", p)
		}
		if ro {
			q.Add("mode", "ro")
		}
		return "file:" + path + "?" + q.Encode()
	}
	w, err := sql.Open("sqlite", dsn(false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	s := &Store{w: w}
	if err := s.migrate(); err != nil {
		_ = w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(true))
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	s.r = r
	return s, nil
}

// Close closes both pools.
func (s *Store) Close() error { return errors.Join(s.r.Close(), s.w.Close()) }

func (s *Store) migrate() error {
	if _, err := s.w.Exec("PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
		return fmt.Errorf("auto_vacuum: %w", err)
	}
	for _, stmt := range schema {
		if _, err := s.w.Exec(stmt); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}
	_, err := s.w.Exec(`INSERT INTO meta (key, value) VALUES ('schema', ?) ON CONFLICT (key) DO NOTHING`, schemaVersion)
	return err
}

func ms(t time.Time) int64     { return t.UnixMilli() }
func minute(t time.Time) int64 { return t.Unix() / 60 * 60 }
func hour(t time.Time) int64   { return t.Unix() / 3600 * 3600 }

type counterKey struct {
	hour               int64
	env, host, service string
	level              int
}

// Write stores a batch of records in one transaction.
func (s *Store) Write(ctx context.Context, recs []record.Record) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	logStmt, err := tx.PrepareContext(ctx, `INSERT INTO logs (ts, env, host, service, level, msg, fields) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	metricStmt, err := tx.PrepareContext(ctx, `INSERT INTO metrics (minute, env, host, name, value) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (env, host, name, minute) DO UPDATE SET value = excluded.value`)
	if err != nil {
		return err
	}
	textStmt, err := tx.PrepareContext(ctx, `INSERT INTO texts (minute, env, host, name, value) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (env, host, name, minute) DO UPDATE SET value = excluded.value`)
	if err != nil {
		return err
	}
	counts := map[counterKey]int{}
	for _, r := range recs {
		switch r.Kind {
		case record.KindLog:
			var fields []byte
			if len(r.Fields) > 0 {
				fields, _ = json.Marshal(r.Fields)
			}
			if _, err := logStmt.ExecContext(ctx, ms(r.TS), r.Env, r.Host, r.Service, r.Level, r.Message, nullBytes(fields)); err != nil {
				return fmt.Errorf("insert log: %w", err)
			}
			counts[counterKey{hour(r.TS), r.Env, r.Host, r.Service, r.Level}]++
		default:
			for name, v := range r.Values {
				if _, err := metricStmt.ExecContext(ctx, minute(r.TS), r.Env, r.Host, name, v); err != nil {
					return fmt.Errorf("insert metric: %w", err)
				}
			}
			for name, v := range r.Texts {
				if _, err := textStmt.ExecContext(ctx, minute(r.TS), r.Env, r.Host, name, v); err != nil {
					return fmt.Errorf("insert text: %w", err)
				}
			}
		}
	}
	for k, n := range counts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO counters (hour, env, host, service, level, n) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (env, host, service, level, hour) DO UPDATE SET n = n + excluded.n`, k.hour, k.env, k.host, k.service, k.level, n); err != nil {
			return fmt.Errorf("counter: %w", err)
		}
	}
	return tx.Commit()
}

func nullBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// Retention per kind.
type Retention struct{ Logs, Metrics, Counters, Incidents time.Duration }

// Retain deletes old rows and returns the number of deleted rows.
func (s *Store) Retain(ctx context.Context, now time.Time, r Retention) (int64, error) {
	var total int64
	for _, q := range []struct {
		sql   string
		limit int64
	}{
		{`DELETE FROM logs WHERE ts < ?`, ms(now.Add(-r.Logs))},
		{`DELETE FROM metrics WHERE minute < ?`, now.Add(-r.Metrics).Unix()},
		{`DELETE FROM texts WHERE minute < ?`, now.Add(-r.Metrics).Unix()},
		{`DELETE FROM counters WHERE hour < ?`, now.Add(-r.Counters).Unix()},
		{`DELETE FROM incidents WHERE status = 'resolved' AND resolved < ?`, ms(now.Add(-r.Incidents))},
		{`DELETE FROM outbox WHERE sent IS NOT NULL AND sent < ?`, ms(now.Add(-r.Incidents))},
	} {
		res, err := s.w.ExecContext(ctx, q.sql, q.limit)
		if err != nil {
			return total, fmt.Errorf("retention: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	if _, err := s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return total, fmt.Errorf("vacuum: %w", err)
	}
	return total, nil
}
