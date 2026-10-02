package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func dur(d time.Duration) config.Duration { return config.Duration(d) }

func engine(t *testing.T, rules ...config.Rule) *Engine {
	t.Helper()
	for i := range rules {
		if rules[i].Severity == "" {
			rules[i].Severity = "warning"
		}
	}
	e, err := New(rules, 2*time.Hour, func(env, host string) string {
		if host == "db1" {
			return "db"
		}
		return "api"
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func val(e *Engine, host, name string, at time.Time, v float64) {
	e.Observe(record.Record{Kind: record.KindMetric, Env: "uat", Host: host, TS: at, Values: map[string]float64{name: v}})
}

func keys(ts []Transition) string {
	var s []string
	for _, t := range ts {
		op := "resolve"
		if t.Open {
			op = "open"
		}
		s = append(s, op+":"+t.Key)
	}
	return strings.Join(s, ",")
}

func TestThresholdWithFor(t *testing.T) {
	e := engine(t, config.Rule{Name: "cpu", Type: "threshold", Series: "cpu.cpu_p", Op: ">", Value: "90", For: dur(5 * time.Minute)})
	steps := []struct {
		min  int
		v    float64
		want string
	}{
		{0, 95, ""},                   // pending
		{2, 97, ""},                   // still pending
		{5, 99, "open:cpu/uat/h1"},    // held 5 min
		{6, 98, ""},                   // no second open
		{7, 50, "resolve:cpu/uat/h1"}, // resolved once
		{8, 95, ""},                   // pending again from scratch
		{10, 50, ""},                  // E2 spike shorter than for: silent
	}
	for _, s := range steps {
		at := t0.Add(time.Duration(s.min) * time.Minute)
		val(e, "h1", "cpu.cpu_p", at, s.v)
		if got := keys(e.Evaluate(at)); got != s.want {
			t.Fatalf("minute %d: got %q want %q", s.min, got, s.want)
		}
	}
}

func TestTextRule(t *testing.T) {
	e := engine(t, config.Rule{Name: "backup", Type: "text", Series: "backup.status", Op: "!=", Value: "ok", Text: "{rule} on {host}: {detail}"})
	e.Observe(record.Record{Kind: record.KindFact, Env: "uat", Host: "db1", TS: t0, Texts: map[string]string{"backup.status": "failed"}})
	tr := e.Evaluate(t0)
	if keys(tr) != "open:backup/uat/db1" || tr[0].Text != `backup on db1: backup.status is "failed"` {
		t.Fatalf("E3 open: %v", tr)
	}
	e.Observe(record.Record{Kind: record.KindFact, Env: "uat", Host: "db1", TS: t0.Add(time.Minute), Texts: map[string]string{"backup.status": "ok"}})
	if got := keys(e.Evaluate(t0.Add(time.Minute))); got != "resolve:backup/uat/db1" {
		t.Fatalf("E3 resolve: %q", got)
	}
}

func TestLogRate(t *testing.T) {
	e := engine(t, config.Rule{Name: "primary", Type: "lograte", Level: "warning", Pattern: "lost as primary", Count: 3, Per: dur(5 * time.Minute),
		Match: config.Match{Service: "api"}})
	logl := func(at time.Time, svc string, lvl int, msg string) {
		e.Observe(record.Record{Kind: record.KindLog, Env: "uat", Host: "h1", TS: at, Service: svc, Level: lvl, Message: msg})
	}
	logl(t0, "api", 4, "db x: lost as primary, re-checking")
	logl(t0.Add(time.Minute), "api", 6, "lost as primary (info level: ignored)")
	logl(t0.Add(time.Minute), "worker", 4, "lost as primary (other service: ignored)")
	logl(t0.Add(2*time.Minute), "api", 3, "lost as primary")
	if got := keys(e.Evaluate(t0.Add(2 * time.Minute))); got != "" {
		t.Fatalf("E4 two matches only: %q", got)
	}
	logl(t0.Add(3*time.Minute), "api", 4, "lost as primary")
	if got := keys(e.Evaluate(t0.Add(3 * time.Minute))); got != "open:primary/uat/h1" {
		t.Fatalf("E4 open: %q", got)
	}
	if got := keys(e.Evaluate(t0.Add(9 * time.Minute))); got != "resolve:primary/uat/h1" {
		t.Fatalf("E4 resolve after the window: %q", got)
	}
}

func TestAnomaly(t *testing.T) {
	e := engine(t, config.Rule{Name: "rps", Type: "anomaly", Series: "api.rps", ZScore: 4, MinSamples: 30, MinDelta: 20})
	for i := 0; i < 40; i++ {
		val(e, "h1", "api.rps", t0.Add(time.Duration(i)*time.Minute), 10+float64(i%3))
	}
	now := t0.Add(40 * time.Minute)
	if got := keys(e.Evaluate(now)); got != "" {
		t.Fatalf("E5 steady: %q", got)
	}
	val(e, "h1", "api.rps", now, 60)
	tr := e.Evaluate(now)
	if keys(tr) != "open:rps/uat/h1" || !strings.Contains(tr[0].Text, "usual") {
		t.Fatalf("E5 spike: %v", tr)
	}
	val(e, "h1", "api.rps", now.Add(time.Minute), 25) // +14 from the mean: below min_delta 20
	if got := keys(e.Evaluate(now.Add(time.Minute))); got != "resolve:rps/uat/h1" {
		t.Fatalf("E5 back to normal: %q", got)
	}
	e2 := engine(t, config.Rule{Name: "rps", Type: "anomaly", Series: "api.rps", ZScore: 4, MinSamples: 30, MinDelta: 20})
	for i := 0; i < 10; i++ {
		val(e2, "h1", "api.rps", t0.Add(time.Duration(i)*time.Minute), 10)
	}
	val(e2, "h1", "api.rps", t0.Add(10*time.Minute), 100)
	if got := keys(e2.Evaluate(t0.Add(10 * time.Minute))); got != "" {
		t.Fatalf("E5 not enough samples: %q", got)
	}
}

func TestStaleMatchRestartOrder(t *testing.T) {
	e := engine(t, config.Rule{Name: "disk", Type: "threshold", Series: "disk.used_pct", Op: ">=", Value: "90", Match: config.Match{Role: "db"}})
	val(e, "db1", "disk.used_pct", t0, 95)
	val(e, "h1", "disk.used_pct", t0, 99) // role api: not matched
	if got := keys(e.Evaluate(t0)); got != "open:disk/uat/db1" {
		t.Fatalf("E7 role match: %q", got)
	}
	if got := keys(e.Evaluate(t0.Add(11 * time.Minute))); got != "resolve:disk/uat/db1" {
		t.Fatalf("E6 stale series resolves: %q", got)
	}

	// E8 restart: open incidents are restored; a held condition does not open again, a gone one resolves
	r := engine(t, config.Rule{Name: "disk", Type: "threshold", Series: "disk.used_pct", Op: ">=", Value: "90"})
	r.SetActive([]string{"disk/uat/db1", "disk/uat/db2"})
	r.ObserveValue("uat", "db1", "disk.used_pct", t0, 96)
	if got := keys(r.Evaluate(t0)); got != "resolve:disk/uat/db2" {
		t.Fatalf("E8 after restart: %q", got)
	}

	// E9 out-of-order values keep time order (the newest decides)
	o := engine(t, config.Rule{Name: "x", Type: "threshold", Series: "m", Op: ">", Value: "5"})
	val(o, "h1", "m", t0.Add(2*time.Minute), 1)
	val(o, "h1", "m", t0.Add(time.Minute), 9)
	if got := keys(o.Evaluate(t0.Add(2 * time.Minute))); got != "" {
		t.Fatalf("E9 older high value must not fire: %q", got)
	}
}

func TestNewErrors(t *testing.T) {
	for _, r := range []config.Rule{
		{Name: "a", Type: "threshold", Series: "m", Op: ">", Value: "x"},
		{Name: "b", Type: "lograte", Pattern: "("},
		{Name: "c", Type: "lograte", Level: "loud"},
	} {
		if _, err := New([]config.Rule{r}, time.Hour, nil); err == nil {
			t.Errorf("rule %s accepted", r.Name)
		}
	}
}

func TestAbsent(t *testing.T) {
	r := config.Rule{Name: "backup-missing", Type: "absent", Series: "backup.age_h", MaxAge: dur(26 * time.Hour), Match: config.Match{Role: "db"}}
	e := engine(t, r)
	val(e, "db1", "backup.age_h", t0, 3)
	val(e, "h1", "backup.age_h", t0, 3) // role api: not watched
	e.Observe(record.Record{Kind: record.KindFact, Env: "uat", Host: "db1", TS: t0, Texts: map[string]string{"backup.status": "ok"}})
	if got := keys(e.Evaluate(t0.Add(25 * time.Hour))); got != "" {
		t.Fatalf("E10 within max_age: %q", got)
	}
	tr := e.Evaluate(t0.Add(27 * time.Hour))
	if keys(tr) != "open:backup-missing/uat/db1" || !strings.Contains(tr[0].Text, "no backup.age_h since 2026-10-02 12:00 UTC") {
		t.Fatalf("E10 absent beyond window and max_age: %v", tr)
	}
	val(e, "db1", "backup.age_h", t0.Add(28*time.Hour), 1)
	if got := keys(e.Evaluate(t0.Add(28 * time.Hour))); got != "resolve:backup-missing/uat/db1" {
		t.Fatalf("E10 back: %q", got)
	}
	// E11 restart: last seen restored from the database
	r2 := engine(t, r)
	r2.ObserveSeen("uat", "db1", "backup.age_h", t0)
	r2.ObserveSeen("uat", "db1", "cpu.cpu_p", t0) // not watched: ignored
	if got := keys(r2.Evaluate(t0.Add(30 * time.Hour))); got != "open:backup-missing/uat/db1" {
		t.Fatalf("E11 restored: %q", got)
	}
	if s := r2.AbsentSeries(); len(s) != 1 || s[0] != "backup.age_h" {
		t.Fatalf("E11 series: %v", s)
	}
}

func TestAbsentOutOfOrder(t *testing.T) {
	e := engine(t, config.Rule{Name: "gone", Type: "absent", Series: "backup.age_h", MaxAge: dur(time.Hour)})
	val(e, "h1", "backup.age_h", t0.Add(2*time.Hour), 1)
	val(e, "h1", "backup.age_h", t0, 1) // late, older value must not move last seen back
	if got := keys(e.Evaluate(t0.Add(150 * time.Minute))); got != "" {
		t.Fatalf("E12 older value moved last seen back: %q", got)
	}
}
