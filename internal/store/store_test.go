package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/record"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func logRec(host, svc string, level int, msg string, ts time.Time) record.Record {
	return record.Record{Kind: record.KindLog, TS: ts, Env: "uat", Host: host, Service: svc, Level: level, Message: msg, Fields: map[string]any{"k": "v"}}
}

func TestWriteAndQuery(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	recs := []record.Record{
		logRec("h1", "api", 6, "hello 50%_off", t0),
		logRec("h1", "api", 3, "boom", t0.Add(time.Second)),
		logRec("h2", "db", 4, "slow", t0.Add(2*time.Second)),
		{Kind: record.KindMetric, TS: t0, Env: "uat", Host: "h1", Values: map[string]float64{"cpu.cpu_p": 10}},
		{Kind: record.KindMetric, TS: t0.Add(20 * time.Second), Env: "uat", Host: "h1", Values: map[string]float64{"cpu.cpu_p": 30}},
		{Kind: record.KindFact, TS: t0, Env: "uat", Host: "h2", Values: map[string]float64{"backup.age_h": 7}, Texts: map[string]string{"backup.status": "ok"}},
	}
	if err := s.Write(ctx, recs); err != nil {
		t.Fatal(err)
	}
	from, to := t0.Add(-time.Hour), t0.Add(time.Hour)

	t.Run("D1_logs_filter_and_cursor", func(t *testing.T) {
		all, next, err := s.Logs(ctx, LogFilter{From: from, To: to, MaxLevel: 7, Limit: 2})
		if err != nil || len(all) != 2 || next == 0 || all[0].Message != "slow" {
			t.Fatalf("page1 %v next %d err %v", all, next, err)
		}
		rest, next2, _ := s.Logs(ctx, LogFilter{From: from, To: to, MaxLevel: 7, Limit: 2, Before: next})
		if len(rest) != 1 || next2 != 0 || rest[0].Message != "hello 50%_off" || rest[0].Fields["k"] != "v" {
			t.Fatalf("page2 %v next %d", rest, next2)
		}
		errs, _, _ := s.Logs(ctx, LogFilter{From: from, To: to, MaxLevel: 4})
		if len(errs) != 2 {
			t.Errorf("level filter: %v", errs)
		}
		like, _, _ := s.Logs(ctx, LogFilter{From: from, To: to, MaxLevel: 7, Text: "50%_"})
		if len(like) != 1 {
			t.Errorf("escaped LIKE: %v", like)
		}
		none, _, _ := s.Logs(ctx, LogFilter{Envs: []string{"prod"}, From: from, To: to, MaxLevel: 7})
		if len(none) != 0 {
			t.Errorf("env filter: %v", none)
		}
	})
	t.Run("D2_metric_last_value_per_minute", func(t *testing.T) {
		pts, err := s.Series(ctx, "uat", "h1", "cpu.cpu_p", from, to)
		if err != nil || len(pts) != 1 || pts[0].V != 30 {
			t.Fatalf("%v %v", pts, err)
		}
	})
	t.Run("D3_counters_per_hour", func(t *testing.T) {
		cs, err := s.Counters(ctx, CounterFilter{From: from, To: to, ByHost: true})
		if err != nil || len(cs) != 3 {
			t.Fatalf("%v %v", cs, err)
		}
		if err := s.Write(ctx, []record.Record{logRec("h1", "api", 3, "again", t0.Add(time.Minute))}); err != nil {
			t.Fatal(err)
		}
		cs, _ = s.Counters(ctx, CounterFilter{From: from, To: to})
		var errors int64
		for _, c := range cs {
			if c.Level == 3 {
				errors = c.N
			}
		}
		if errors != 2 {
			t.Errorf("error count %d, want 2 (summed across batches)", errors)
		}
	})
	t.Run("D4_values_since_for_window_rebuild", func(t *testing.T) {
		var nums, texts int
		err := s.ValuesSince(ctx, from, func(v SeriesValue) {
			if v.IsText {
				texts++
				if v.Text != "ok" {
					t.Errorf("text %+v", v)
				}
			} else {
				nums++
			}
		})
		if err != nil || nums != 2 || texts != 1 {
			t.Fatalf("nums %d texts %d err %v", nums, texts, err)
		}
	})
}

func TestIncidentsAndOutbox(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	in := Incident{Key: "cpu/uat/h1", Rule: "cpu", Env: "uat", Host: "h1", Severity: "warning", Opened: t0, Text: "CPU high"}
	id, ok, err := s.OpenIncident(ctx, in)
	if err != nil || !ok || id == 0 {
		t.Fatalf("open: %d %v %v", id, ok, err)
	}
	if _, ok, _ := s.OpenIncident(ctx, in); ok {
		t.Error("I1: second open of the same key accepted")
	}
	keys, _ := s.OpenIncidentKeys(ctx)
	if _, ok := keys["cpu/uat/h1"]; !ok {
		t.Error("I2: open key not listed")
	}
	res, ok, err := s.ResolveIncident(ctx, "cpu/uat/h1", t0.Add(time.Minute))
	if err != nil || !ok || res.Status != StatusResolved || res.Resolved == nil {
		t.Fatalf("I3 resolve: %+v %v %v", res, ok, err)
	}
	if _, ok, _ := s.ResolveIncident(ctx, "cpu/uat/h1", t0); ok {
		t.Error("I4: resolved twice")
	}
	if _, ok, _ := s.OpenIncident(ctx, in); !ok {
		t.Error("I5: key cannot open again after resolve")
	}
	list, _ := s.Incidents(ctx, IncidentFilter{})
	if len(list) != 2 {
		t.Errorf("I6: %d incidents", len(list))
	}

	if err := s.Enqueue(ctx, "alarms", "tg/ops", "hi", id, t0, t0); err != nil {
		t.Fatal(err)
	}
	due, _ := s.Due(ctx, t0, 10)
	if len(due) != 1 || due[0].Incident != id || due[0].Dest != "tg/ops" || due[0].Route != "alarms" {
		t.Fatalf("O1 due: %+v", due)
	}
	_ = s.MarkFailed(ctx, due[0].ID, t0.Add(time.Minute), "down")
	if due, _ := s.Due(ctx, t0.Add(30*time.Second), 10); len(due) != 0 {
		t.Error("O2: due before next_try")
	}
	due, _ = s.Due(ctx, t0.Add(time.Minute), 10)
	if len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("O3: %+v", due)
	}
	_ = s.MarkSent(ctx, due[0].ID, t0.Add(time.Minute))
	if n, _ := s.PendingCount(ctx); n != 0 {
		t.Errorf("O4 pending %d", n)
	}
	// O5 digest: held until notBefore, Pending returns the whole group
	_ = s.Enqueue(ctx, "daily", "mail", "a", 0, t0, t0.Add(time.Hour))
	_ = s.Enqueue(ctx, "daily", "mail", "b", 0, t0.Add(time.Minute), t0.Add(time.Hour+time.Minute))
	_ = s.Enqueue(ctx, "daily", "tg", "c", 0, t0, t0.Add(time.Hour))
	if due, _ := s.Due(ctx, t0.Add(59*time.Minute), 10); len(due) != 0 {
		t.Error("O5 digest due early")
	}
	if p, _ := s.Pending(ctx, "daily", "mail"); len(p) != 2 || p[0].Text != "a" || p[1].Text != "b" {
		t.Errorf("O5 pending group: %+v", p)
	}
}

func TestOutboxMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s := open1(t, path)
	_, _ = s.w.Exec(`DROP TABLE outbox`)
	_, _ = s.w.Exec(`CREATE TABLE outbox (id INTEGER PRIMARY KEY, created INTEGER NOT NULL, route TEXT NOT NULL, text TEXT NOT NULL,
		incident INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL, sent INTEGER, error TEXT NOT NULL DEFAULT '')`)
	_ = s.Close()
	s = open1(t, path)
	defer s.Close()
	if err := s.Enqueue(context.Background(), "r", "d", "x", 0, t0, t0); err != nil {
		t.Fatalf("O6 old database not migrated: %v", err)
	}
}

func open1(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHostsAndRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seen := t0
	if err := s.SaveHosts(ctx, []Host{{Env: "uat", Host: "h1", IP: "100.1.1.1", Role: "api", Status: "up", LastSeen: &seen, Known: true, Last: map[string]float64{"cpu.cpu_p": 3}}}); err != nil {
		t.Fatal(err)
	}
	hs, err := s.Hosts(ctx, []string{"uat"})
	if err != nil || len(hs) != 1 || hs[0].IP != "100.1.1.1" || hs[0].Last["cpu.cpu_p"] != 3 || !hs[0].LastSeen.Equal(t0) {
		t.Fatalf("H1 %+v %v", hs, err)
	}
	if hs, _ := s.Hosts(ctx, []string{"prod"}); len(hs) != 0 {
		t.Error("H2 env filter")
	}
	old := t0.Add(-6 * 24 * time.Hour)
	_ = s.Write(ctx, []record.Record{logRec("h1", "a", 6, "old", old), logRec("h1", "a", 6, "new", t0),
		{Kind: record.KindMetric, TS: old, Env: "uat", Host: "h1", Values: map[string]float64{"m": 1}}})
	n, err := s.Retain(ctx, t0, Retention{Logs: 5 * 24 * time.Hour, Metrics: 5 * 24 * time.Hour, Counters: 90 * 24 * time.Hour, Incidents: 90 * 24 * time.Hour})
	if err != nil || n != 2 {
		t.Fatalf("R1 deleted %d err %v", n, err)
	}
	logs, _, _ := s.Logs(ctx, LogFilter{From: old.Add(-time.Hour), To: t0.Add(time.Hour), MaxLevel: 7})
	if len(logs) != 1 || logs[0].Message != "new" {
		t.Errorf("R2 %v", logs)
	}
}

func TestLastSeen(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.Write(ctx, []record.Record{
		{Kind: record.KindMetric, TS: t0, Env: "uat", Host: "db1", Values: map[string]float64{"backup.age_h": 1}},
		{Kind: record.KindMetric, TS: t0.Add(time.Hour), Env: "uat", Host: "db1", Values: map[string]float64{"backup.age_h": 2, "cpu.cpu_p": 1}},
		{Kind: record.KindFact, TS: t0.Add(2 * time.Hour), Env: "uat", Host: "db2", Texts: map[string]string{"backup.status": "ok"}},
	})
	got := map[string]time.Time{}
	if err := s.LastSeen(ctx, []string{"backup.age_h", "backup.status"}, func(env, host, name string, t time.Time) { got[host+"/"+name] = t }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["db1/backup.age_h"].Equal(t0.Add(time.Hour).Truncate(time.Minute)) || !got["db2/backup.status"].Equal(t0.Add(2*time.Hour).Truncate(time.Minute)) {
		t.Fatalf("LS1: %v", got)
	}
}
