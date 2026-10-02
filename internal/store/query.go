package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// LogLine is a stored log line.
type LogLine struct {
	ID      int64          `json:"id"`
	TS      time.Time      `json:"ts"`
	Env     string         `json:"env"`
	Host    string         `json:"host"`
	Service string         `json:"service"`
	Level   int            `json:"level"`
	Message string         `json:"msg"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// LogFilter selects log lines (newest first, cursor = last id of the previous page).
type LogFilter struct {
	Envs     []string
	Host     string
	Service  string
	MaxLevel int // include lines with level <= MaxLevel (7 = all)
	Text     string
	From, To time.Time
	Before   int64 // cursor
	Limit    int
}

// Logs returns one page of log lines and the cursor of the next page (0 = end).
func (s *Store) Logs(ctx context.Context, f LogFilter) ([]LogLine, int64, error) {
	q := strings.Builder{}
	q.WriteString(`SELECT id, ts, env, host, service, level, msg, fields FROM logs WHERE ts >= ? AND ts <= ? AND level <= ?`)
	args := []any{ms(f.From), ms(f.To), f.MaxLevel}
	add := func(cond string, v any) { q.WriteString(" AND " + cond); args = append(args, v) }
	if f.Envs != nil {
		q.WriteString(" AND env IN " + placeholders(len(f.Envs)))
		args = append(args, anys(f.Envs)...)
	}
	if f.Host != "" {
		add("host = ?", f.Host)
	}
	if f.Service != "" {
		add("service = ?", f.Service)
	}
	if f.Text != "" {
		add(`msg LIKE ? ESCAPE '\'`, "%"+escapeLike(f.Text)+"%")
	}
	if f.Before > 0 {
		add("id < ?", f.Before)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q.WriteString(" ORDER BY id DESC LIMIT ?")
	args = append(args, f.Limit+1)
	rows, err := s.r.QueryContext(ctx, q.String(), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []LogLine{}
	for rows.Next() {
		var l LogLine
		var ts int64
		var fields sql.NullString
		if err := rows.Scan(&l.ID, &ts, &l.Env, &l.Host, &l.Service, &l.Level, &l.Message, &fields); err != nil {
			return nil, 0, err
		}
		l.TS = time.UnixMilli(ts).UTC()
		if fields.Valid {
			_ = json.Unmarshal([]byte(fields.String), &l.Fields)
		}
		out = append(out, l)
	}
	var next int64
	if len(out) > f.Limit {
		out = out[:f.Limit]
		next = out[len(out)-1].ID
	}
	return out, next, rows.Err()
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Point is one value of a series.
type Point struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// Series returns the 1-minute values of one metric of a host.
func (s *Store) Series(ctx context.Context, env, host, name string, from, to time.Time) ([]Point, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT minute, value FROM metrics WHERE env = ? AND host = ? AND name = ? AND minute >= ? AND minute <= ? ORDER BY minute`,
		env, host, name, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Point{}
	for rows.Next() {
		var m int64
		var p Point
		if err := rows.Scan(&m, &p.V); err != nil {
			return nil, err
		}
		p.T = time.Unix(m, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// SeriesNames lists the metric names of a host seen since a time.
func (s *Store) SeriesNames(ctx context.Context, env, host string, since time.Time) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT DISTINCT name FROM metrics WHERE env = ? AND host = ? AND minute >= ? ORDER BY name`, env, host, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Counter is the number of log lines of one hour.
type Counter struct {
	Hour    time.Time `json:"hour"`
	Env     string    `json:"env"`
	Host    string    `json:"host,omitempty"`
	Service string    `json:"service,omitempty"`
	Level   int       `json:"level"`
	N       int64     `json:"n"`
}

// CounterFilter selects and groups counters.
type CounterFilter struct {
	Envs     []string
	From, To time.Time
	ByHost   bool
	ByServ   bool
}

// Counters returns log lines per hour and level, optionally per host/service.
func (s *Store) Counters(ctx context.Context, f CounterFilter) ([]Counter, error) {
	cols := "hour, env, level"
	if f.ByHost {
		cols += ", host"
	}
	if f.ByServ {
		cols += ", service"
	}
	q, args := "SELECT "+cols+", sum(n) FROM counters WHERE hour >= ? AND hour <= ?", []any{f.From.Unix(), f.To.Unix()}
	if f.Envs != nil {
		q, args = q+" AND env IN "+placeholders(len(f.Envs)), append(args, anys(f.Envs)...)
	}
	rows, err := s.r.QueryContext(ctx, q+" GROUP BY "+cols+" ORDER BY hour", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Counter{}
	for rows.Next() {
		var c Counter
		var h int64
		dest := []any{&h, &c.Env, &c.Level}
		if f.ByHost {
			dest = append(dest, &c.Host)
		}
		if f.ByServ {
			dest = append(dest, &c.Service)
		}
		dest = append(dest, &c.N)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		c.Hour = time.Unix(h, 0).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// SeriesValue is one stored value of any series (window rebuild).
type SeriesValue struct {
	Env, Host, Name string
	T               time.Time
	V               float64
	Text            string
	IsText          bool
}

// ValuesSince calls fn for every metric and text value since t, oldest first.
func (s *Store) ValuesSince(ctx context.Context, t time.Time, fn func(SeriesValue)) error {
	for _, q := range []struct {
		sql    string
		isText bool
	}{
		{`SELECT minute, env, host, name, value FROM metrics WHERE minute >= ? ORDER BY minute`, false},
		{`SELECT minute, env, host, name, value FROM texts WHERE minute >= ? ORDER BY minute`, true},
	} {
		rows, err := s.r.QueryContext(ctx, q.sql, t.Unix())
		if err != nil {
			return err
		}
		for rows.Next() {
			var v SeriesValue
			var m int64
			var raw any
			if err := rows.Scan(&m, &v.Env, &v.Host, &v.Name, &raw); err != nil {
				rows.Close()
				return err
			}
			v.T, v.IsText = time.Unix(m, 0).UTC(), q.isText
			switch x := raw.(type) {
			case float64:
				v.V = x
			case int64:
				v.V = float64(x)
			case string:
				v.Text = x
				if !q.isText {
					v.V, _ = strconv.ParseFloat(x, 64)
				}
			}
			fn(v)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

// LogsSince calls fn for every log line since t, oldest first (window rebuild for log rules).
func (s *Store) LogsSince(ctx context.Context, t time.Time, fn func(LogLine)) error {
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, env, host, service, level, msg FROM logs WHERE ts >= ? ORDER BY ts`, ms(t))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var l LogLine
		var ts int64
		if err := rows.Scan(&l.ID, &ts, &l.Env, &l.Host, &l.Service, &l.Level, &l.Message); err != nil {
			return err
		}
		l.TS = time.UnixMilli(ts).UTC()
		fn(l)
	}
	return rows.Err()
}
