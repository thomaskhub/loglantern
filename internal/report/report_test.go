package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/notify"
	"github.com/thomkin/loglantern/internal/record"
	"github.com/thomkin/loglantern/internal/store"
)

func TestReport(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 2, 6, 0, 0, 0, time.UTC)
	seen := now.Add(-time.Minute)
	_ = st.SaveHosts(ctx, []store.Host{
		{Env: "uat", Host: "api1", Status: "up", LastSeen: &seen, Last: map[string]float64{"lightsail.burst_pct": 12}},
		{Env: "uat", Host: "db1", Status: "missing", LastSeen: &seen},
		{Env: "prod", Host: "p1", Status: "up", LastSeen: &seen},
	})
	_, _, _ = st.OpenIncident(ctx, store.Incident{Key: "cpu/uat/api1", Rule: "cpu", Env: "uat", Host: "api1", Severity: "warning", Opened: now.Add(-2 * time.Hour), Text: "cpu high"})
	_, _, _ = st.OpenIncident(ctx, store.Incident{Key: "disk/uat/db1", Rule: "disk", Env: "uat", Host: "db1", Severity: "critical", Opened: now.Add(-3 * time.Hour), Text: "disk"})
	_, _, _ = st.ResolveIncident(ctx, "disk/uat/db1", now.Add(-time.Hour))
	var recs []record.Record
	for i := range 5 {
		recs = append(recs, record.Record{Kind: record.KindLog, TS: now.Add(-time.Duration(i+1) * time.Hour), Env: "uat", Host: "api1", Service: "api", Level: 3, Message: "e"})
	}
	recs = append(recs,
		record.Record{Kind: record.KindLog, TS: now.Add(-time.Hour), Env: "uat", Host: "api1", Service: "worker", Level: 2, Message: "e"},
		record.Record{Kind: record.KindLog, TS: now.Add(-time.Hour), Env: "uat", Host: "api1", Service: "api", Level: 6, Message: "info"},
		record.Record{Kind: record.KindLog, TS: now.Add(-30 * time.Hour), Env: "uat", Host: "api1", Service: "api", Level: 3, Message: "old"})
	_ = st.Write(ctx, recs)

	text, err := Build(ctx, st, []string{"uat", "prod"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PROD: 1 hosts, 1 up",
		"UAT: 2 hosts, 1 up, not reporting: db1",
		"Incidents: 2 new (critical 1, warning 1, info 0), 1 still open",
		"open #1 cpu/api1",
		"Error lines: 6 (day before: 1)",
		"Noisiest: api 5, worker 1",
		"Low CPU burst capacity: api1 12%",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Y1 missing %q in:\n%s", want, text)
		}
	}
	if strings.Index(text, "PROD") > strings.Index(text, "UAT") {
		t.Error("Y1 envs sorted")
	}

	for _, c := range []struct {
		at   time.Time
		want bool
	}{{now.Add(-time.Minute), false}, {now, true}, {now.Add(5 * time.Hour), true}} {
		if got, _ := Due(ctx, st, "06:00", c.at); got != c.want {
			t.Errorf("Y2 due at %s: %v", c.at, got)
		}
	}
	if text, err := Send(ctx, st, notify.NewOutbox(st, &config.Config{Routes: []config.Route{{Name: "daily", Send: []string{"tg/daily"}}}}), []string{"uat"}, "daily", now); err != nil || !strings.HasPrefix(text, "Daily report") {
		t.Fatal(err)
	}
	if got, _ := Due(ctx, st, "06:00", now.Add(time.Hour)); got {
		t.Error("Y3 sent twice the same day (restart)")
	}
	if got, _ := Due(ctx, st, "06:00", now.Add(24*time.Hour)); !got {
		t.Error("Y3 next day not due")
	}
	msgs, _ := st.Due(ctx, now, 10)
	if len(msgs) != 1 || msgs[0].Route != "daily" || msgs[0].Dest != "tg/daily" {
		t.Errorf("Y4 queued: %+v", msgs)
	}
}
