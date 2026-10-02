package hosts

import (
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/record"
	"github.com/thomaskhub/loglantern/internal/store"
)

func TestRegistry(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r := New([]store.Host{{Env: "uat", Host: "db", Role: "db"}}, nil, 3*time.Minute, t0)
	seen := func(host string, at time.Time) {
		r.Seen(record.Record{Env: "uat", Host: host, TS: at, IP: "100.0.0.1", Role: "api", Values: map[string]float64{"cpu.cpu_p": 5}})
	}
	if c := r.Check(t0.Add(time.Minute)); len(c) != 0 || r.Snapshot()[0].Status != Unknown {
		t.Fatalf("H1 known host unknown during grace: %v %v", c, r.Snapshot())
	}
	if c := r.Check(t0.Add(4 * time.Minute)); len(c) != 1 || !c[0].Missing || c[0].Host != "db" {
		t.Fatalf("H2 known host never seen → missing: %v", c)
	}
	if c := r.Check(t0.Add(5 * time.Minute)); len(c) != 0 {
		t.Fatalf("H3 missing reported twice: %v", c)
	}
	seen("api", t0.Add(5*time.Minute))
	seen("db", t0.Add(5*time.Minute))
	if c := r.Check(t0.Add(5 * time.Minute)); len(c) != 1 || c[0].Missing || c[0].Host != "db" {
		t.Fatalf("H4 db back: %v", c)
	}
	if r.Role("uat", "db") != "api" || r.Role("uat", "api") != "api" {
		t.Errorf("H5 roles from records: %q %q", r.Role("uat", "db"), r.Role("uat", "api"))
	}
	if c := r.Check(t0.Add(9 * time.Minute)); len(c) != 2 {
		t.Fatalf("H6 both silent > 3 min: %v", c)
	}
	snap := r.Snapshot()
	if snap[0].Last["cpu.cpu_p"] != 5 || snap[0].IP != "100.0.0.1" {
		t.Errorf("H7 snapshot %+v", snap[0])
	}
	// out-of-order record does not move last_seen back
	seen("api", t0)
	if !r.Snapshot()[0].LastSeen.Equal(t0.Add(5 * time.Minute)) {
		t.Error("H8 last_seen moved back")
	}
}

func TestSyntheticNoHeartbeat(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r := New([]store.Host{{Env: "uat", Host: "db"}}, nil, 3*time.Minute, t0)
	r.Seen(record.Record{Env: "uat", Host: "db", TS: t0, Synthetic: true, Values: map[string]float64{"lightsail.burst_pct": 20}})
	r.Seen(record.Record{Env: "uat", Host: "probe", TS: t0, Synthetic: true, Values: map[string]float64{"probe.x.up": 1}})
	snap := r.Snapshot()
	if len(snap) != 1 || snap[0].LastSeen != nil || snap[0].Last["lightsail.burst_pct"] != 20 {
		t.Fatalf("H9 synthetic: %+v", snap)
	}
	if c := r.Check(t0.Add(4 * time.Minute)); len(c) != 1 || !c[0].Missing {
		t.Fatalf("H9 dead VM with Lightsail data still missing: %v", c)
	}
}

func TestRestartGrace(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	old := t0.Add(-time.Hour)
	r := New(nil, []store.Host{{Env: "uat", Host: "a", Status: Up, LastSeen: &old}, {Env: "uat", Host: "b", Status: Missing, LastSeen: &old}}, 3*time.Minute, t0)
	if c := r.Check(t0.Add(time.Minute)); len(c) != 0 {
		t.Fatalf("H10 up host flagged during restart grace, or missing host re-reported: %v", c)
	}
	if c := r.Check(t0.Add(4 * time.Minute)); len(c) != 1 || c[0].Host != "a" || !c[0].Missing {
		t.Fatalf("H10 after grace: %v", c)
	}
}
