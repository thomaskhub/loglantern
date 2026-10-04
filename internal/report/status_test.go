package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/store"
)

func TestBuildStatus(t *testing.T) {
	now := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	seen := now.Add(-time.Minute)
	old := now.Add(-12 * time.Minute)
	hosts := []store.Host{
		{Env: "uat", Host: "ishanga-api-eu-uat", Status: "up", LastSeen: &seen,
			Last: map[string]float64{"cpu.cpu_p": 12.4, "mem.used_pct": 41.2, "mem.swap_pct": 3, "disk.used_pct": 55}},
		{Env: "uat", Host: "ishanga-postgres-primary-uat", Status: "missing", LastSeen: &old},
		{Env: "uat", Host: "ishanga-gateway-uat", Status: "unknown",
			Last: map[string]float64{"cpu.cpu_p": 1, "mem.Mem.used": 500, "mem.Mem.total": 1000}},
		{Env: "prod", Host: "p1", Status: "up", LastSeen: &seen},
	}
	got := BuildStatus(hosts, map[string]int{"uat": 2, "prod": 0}, now, time.UTC)
	for _, want := range []string{
		"Status PROD 2026-10-04 14:00 UTC",
		"Status UAT 2026-10-04 14:00 UTC",
		"api-eu ",           // prefix "ishanga-" and suffix "-uat" dropped
		"postgres-primary",  // not cut further
		"MISS",              // missing host
		"Open incidents: 2", // per environment
		"Not reporting: postgres-primary (12m0s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "api-eu            up    12  41   3  55") {
		t.Errorf("api-eu row wrong:\n%s", got)
	}
	if !strings.Contains(got, "gateway           ?      1  50   -   -") { // mem from used/total, no swap or disk
		t.Errorf("gateway row wrong:\n%s", got)
	}
	if strings.Count(got, "```") != 4 {
		t.Errorf("want two fenced tables, got:\n%s", got)
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
