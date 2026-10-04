package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/notify"
	"github.com/thomaskhub/loglantern/internal/record"
	"github.com/thomaskhub/loglantern/internal/store"
)

func TestBuildStatus(t *testing.T) {
	now := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	seen := now.Add(-time.Minute)
	old := now.Add(-12 * time.Minute)
	rows := []Row{
		{Host: store.Host{Env: "uat", Host: "ishanga-api-eu-uat", Status: "up", LastSeen: &seen, Last: map[string]float64{"disk.used_pct": 55}},
			CPU: Stat{Avg: 12.4, Max: 61.6, OK: true}, Mem: Stat{Avg: 41.2, Max: 44, OK: true}, Swap: Stat{Avg: 3, Max: 3, OK: true}},
		{Host: store.Host{Env: "uat", Host: "ishanga-postgres-primary-uat", Status: "missing", LastSeen: &old}},
		{Host: store.Host{Env: "uat", Host: "ishanga-gateway-uat", Status: "unknown"}, CPU: Stat{Avg: 1, Max: 1, OK: true}},
		{Host: store.Host{Env: "prod", Host: "p1", Status: "up", LastSeen: &seen}},
	}
	got := BuildStatus(rows, map[string]int{"uat": 2, "prod": 0}, 2*time.Hour, now, time.UTC)
	for _, want := range []string{
		"Status PROD 2026-10-04 14:00 UTC, avg/peak of the last 2h0m0s",
		"Status UAT 2026-10-04 14:00 UTC, avg/peak of the last 2h0m0s",
		"api-eu ",
		"postgres-primary",
		"MISS",
		"Open incidents: 2",
		"Not reporting: postgres-primary (12m0s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "api-eu            up   12/62   41/44   3/3    55") {
		t.Errorf("api-eu row wrong:\n%s", got)
	}
	if !strings.Contains(got, "gateway           ?    1/1     -       -       -") {
		t.Errorf("gateway row wrong:\n%s", got)
	}
	if strings.Count(got, "```") != 4 {
		t.Errorf("want two fenced tables, got:\n%s", got)
	}
}

// The values come from the stored 1-minute series of the window, not from the last value.
func TestSendStatusAveragesTheWindow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	var recs []record.Record
	for i, cpu := range []float64{10, 20, 90} { // 3 minutes inside the window
		ts := now.Add(-time.Duration(3-i) * time.Minute)
		recs = append(recs, record.Record{Kind: record.KindMetric, TS: ts, Env: "uat", Host: "api1",
			Values: map[string]float64{"cpu.cpu_p": cpu, "mem.Mem.used": 400, "mem.Mem.total": 1000}})
	}
	recs = append(recs, record.Record{Kind: record.KindMetric, TS: now.Add(-3 * time.Hour), Env: "uat", Host: "api1",
		Values: map[string]float64{"cpu.cpu_p": 100}}) // before the window: ignored
	if err := st.Write(ctx, recs); err != nil {
		t.Fatal(err)
	}
	seen := now
	out := notify.NewOutbox(st, &config.Config{Routes: []config.Route{{Name: "s", Send: []string{"w/x"}}}})
	text, err := SendStatus(ctx, st, out, []store.Host{{Env: "uat", Host: "api1", Status: "up", LastSeen: &seen, Last: map[string]float64{"cpu.cpu_p": 90}}}, "s", 2*time.Hour, time.UTC, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "api1  up   40/90   40/40") { // avg(10,20,90)=40, last value 90 is the peak; mem 400/1000
		t.Errorf("window average missing:\n%s", text)
	}
}

func TestStatusDue(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	every := 2 * time.Hour
	at := time.Date(2026, 10, 4, 14, 5, 0, 0, time.UTC)
	if due, err := StatusDue(ctx, st, every, at); err != nil || !due {
		t.Fatalf("first run must be due, got %v %v", due, err)
	}
	if err := st.SetMeta(ctx, statusKey, slot(every, at)); err != nil {
		t.Fatal(err)
	}
	if due, _ := StatusDue(ctx, st, every, at.Add(50*time.Minute)); due {
		t.Error("same slot (14:00-16:00) must not be due again")
	}
	if due, _ := StatusDue(ctx, st, every, at.Add(2*time.Hour)); !due {
		t.Error("next slot (16:00) must be due")
	}
}
