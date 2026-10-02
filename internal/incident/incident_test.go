package incident

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/hosts"
	"github.com/thomkin/loglantern/internal/rules"
	"github.com/thomkin/loglantern/internal/store"
)

var (
	t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	no = false
)

func setup(t *testing.T, enrich Enricher) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{
		Rules: []config.Rule{{Name: "cpu", Severity: "warning"}, {Name: "errors", Severity: "critical", Match: config.Match{Service: "api"}}},
		Routes: []config.Route{
			{Name: "all", Send: []string{"tg/alerts"}},
			{Name: "prod-critical", Send: []string{"hook", "mail"}, SendResolved: &no, Match: config.Match{Env: "prod", Severity: []string{"critical"}}},
			{Name: "db", Send: []string{"tg/db"}, Match: config.Match{Role: "db"}},
			{Name: "api-svc", Send: []string{"tg"}, Match: config.Match{Service: "api"}},
		},
	}
	role := func(env, host string) string {
		if strings.HasPrefix(host, "db") {
			return "db"
		}
		return "api"
	}
	return New(st, cfg, role, enrich, slog.New(slog.NewTextHandler(io.Discard, nil))), st
}

func due(t *testing.T, st *store.Store) []string {
	t.Helper()
	ms, err := st.Due(context.Background(), t0.Add(24*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		out = append(out, m.Route+"|"+m.Text)
		if m.Route == "prod-critical" {
			out[len(out)-1] = m.Route + ">" + m.Dest + "|" + m.Text
		}
		_ = st.MarkSent(context.Background(), m.ID, t0)
	}
	return out
}

func TestOpenResolveOnce(t *testing.T) {
	m, st := setup(t, nil)
	ctx := context.Background()
	open := rules.Transition{Key: "cpu/uat/h1", Rule: "cpu", Env: "uat", Host: "h1", Severity: "warning", Open: true, Text: "cpu high"}
	if err := m.Handle(ctx, []rules.Transition{open, open}, t0); err != nil {
		t.Fatal(err)
	}
	got := due(t, st)
	if len(got) != 1 || got[0] != "all|[WARNING] uat/h1 #1: cpu high" {
		t.Fatalf("I1 open once: %q", got)
	}
	res := rules.Transition{Key: "cpu/uat/h1", Rule: "cpu", Env: "uat", Host: "h1"}
	if err := m.Handle(ctx, []rules.Transition{res, res}, t0.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got = due(t, st)
	if len(got) != 1 || got[0] != "all|[RESOLVED] uat/h1 #1 after 12m: cpu high" {
		t.Fatalf("I2 resolve once: %q", got)
	}
	// I3: reopen after resolve is a new incident
	_ = m.Handle(ctx, []rules.Transition{open}, t0.Add(20*time.Minute))
	if got = due(t, st); len(got) != 1 || !strings.Contains(got[0], "#2") {
		t.Fatalf("I3 reopen: %q", got)
	}
}

func TestFanOutAndSendResolved(t *testing.T) {
	m, st := setup(t, nil)
	ctx := context.Background()
	open := rules.Transition{Key: "cpu/prod/h1", Rule: "cpu", Env: "prod", Host: "h1", Severity: "critical", Open: true, Text: "cpu high"}
	_ = m.Handle(ctx, []rules.Transition{open}, t0)
	got := strings.Join(due(t, st), "\n")
	for _, want := range []string{"all|[CRITICAL]", "prod-critical>hook|[CRITICAL]", "prod-critical>mail|[CRITICAL]"} {
		if !strings.Contains(got, want) {
			t.Errorf("I8 fan-out lacks %q:\n%s", want, got)
		}
	}
	_ = m.Handle(ctx, []rules.Transition{{Key: "cpu/prod/h1", Rule: "cpu", Env: "prod", Host: "h1", Severity: "critical"}}, t0.Add(time.Minute))
	if got := due(t, st); len(got) != 1 || !strings.HasPrefix(got[0], "all|[RESOLVED]") {
		t.Fatalf("I9 send_resolved false: %q", got)
	}
}

func TestRouting(t *testing.T) {
	m, _ := setup(t, nil)
	for _, c := range []struct {
		t    rules.Transition
		want string
	}{
		{rules.Transition{Rule: "cpu", Env: "uat", Host: "h1", Severity: "warning"}, "all"},
		{rules.Transition{Rule: "cpu", Env: "prod", Host: "h1", Severity: "critical"}, "all,prod-critical"},
		{rules.Transition{Rule: "cpu", Env: "prod", Host: "db1", Severity: "warning"}, "all,db"},
		{rules.Transition{Rule: "errors", Env: "uat", Host: "h1", Severity: "critical"}, "all,api-svc"},
	} {
		if got := strings.Join(m.Routes(c.t), ","); got != c.want {
			t.Errorf("I4 %+v: got %s want %s", c.t, got, c.want)
		}
	}
}

func TestHostMissing(t *testing.T) {
	m, st := setup(t, nil)
	seen := t0.Add(-5 * time.Minute)
	ctx := context.Background()
	_ = m.Handle(ctx, HostTransitions([]hosts.Change{{Env: "uat", Host: "db1", Missing: true, LastSeen: &seen}, {Env: "uat", Host: "h9", Missing: true}}), t0)
	got := due(t, st)
	if len(got) != 3 || !strings.Contains(got[0], "last seen 2026-10-02 11:55 UTC") || !strings.Contains(strings.Join(got, "\n"), "h9 (uat) sends no data, last seen never") {
		t.Fatalf("I5 missing: %q", got)
	}
	_ = m.Handle(ctx, HostTransitions([]hosts.Change{{Env: "uat", Host: "db1"}}), t0.Add(3*time.Minute))
	got = due(t, st)
	if len(got) != 2 || !strings.HasSuffix(got[0], "after 3m: db1 (uat) sends data again") {
		t.Fatalf("I6 back: %q", got)
	}
}

func TestEnrichment(t *testing.T) {
	m, st := setup(t, func(ctx context.Context, in store.Incident, role, service string) ([]Note, error) {
		if in.Host == "bad" {
			return nil, errors.New("down")
		}
		if role != "api" {
			t.Errorf("I7 role passed: %q", role)
		}
		return []Note{{Agent: "explain", Text: "probably a backup job"}, {Agent: "dba", Text: "check locks", Route: "db"}, {Agent: "empty", Text: " "}}, nil
	})
	ctx := context.Background()
	_ = m.Handle(ctx, []rules.Transition{
		{Key: "cpu/uat/h1", Rule: "cpu", Env: "uat", Host: "h1", Severity: "warning", Open: true, Text: "cpu high"},
		{Key: "cpu/uat/bad", Rule: "cpu", Env: "uat", Host: "bad", Severity: "warning", Open: true, Text: "cpu high"},
	}, t0)
	m.Wait()
	got := due(t, st)
	all := strings.Join(got, "\n")
	if len(got) != 4 || !strings.Contains(all, "all|[AI explain] uat/h1 #1: probably a backup job") || !strings.Contains(all, "db|[AI dba] uat/h1 #1: check locks") {
		t.Fatalf("I7 follow-ups (incident routes, own route, empty skipped): %q", got)
	}
	ins, _ := st.Incidents(ctx, store.IncidentFilter{})
	for _, in := range ins {
		if (in.Host == "h1") != (in.AIText == "explain: probably a backup job\n\ndba: check locks") {
			t.Fatalf("I7 ai text stored: %+v", in)
		}
	}
}

func TestShort(t *testing.T) {
	for d, want := range map[time.Duration]string{45 * time.Second: "45s", 12 * time.Minute: "12m", 185 * time.Minute: "3h05m", 52 * time.Hour: "2d04h"} {
		if got := Short(d); got != want {
			t.Errorf("%v: %s", d, got)
		}
	}
}

func TestSilenceAndReminder(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{
		Rules:  []config.Rule{{Name: "cpu", Severity: "warning"}, {Name: "disk", Severity: "critical"}},
		Routes: []config.Route{{Name: "all", Send: []string{"tg"}, Repeat: config.Duration(4 * time.Hour)}, {Name: "quiet", Send: []string{"mail"}}},
		Maintenance: []config.Maintenance{{Name: "nightly", Match: config.Match{Host: "db1"}, From: "23:00", To: "01:00"}},
	}
	m := New(st, cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	open := func(rule, host string) rules.Transition {
		return rules.Transition{Key: rule + "/uat/" + host, Rule: rule, Env: "uat", Host: host, Severity: "warning", Open: true, Text: rule + " high"}
	}
	resolve := func(rule, host string) rules.Transition {
		return rules.Transition{Key: rule + "/uat/" + host, Rule: rule, Env: "uat", Host: host}
	}

	// I10 silenced incident: recorded, not sent; announced late once the silence ends
	_, _ = st.AddSilence(ctx, store.Silence{Host: "h1", Starts: t0.Add(-time.Minute), Ends: t0.Add(time.Hour), Comment: "deploy", Created: t0})
	_ = m.Handle(ctx, []rules.Transition{open("cpu", "h1")}, t0)
	if got := due(t, st); len(got) != 0 {
		t.Fatalf("I10 silenced but sent: %q", got)
	}
	_ = m.Sweep(ctx, t0.Add(30*time.Minute))
	if got := due(t, st); len(got) != 0 {
		t.Fatalf("I10 sent during silence: %q", got)
	}
	_ = m.Sweep(ctx, t0.Add(61*time.Minute))
	got := due(t, st)
	if len(got) != 2 || !strings.Contains(got[0], "(open since 1h01m)") {
		t.Fatalf("I10 late announcement: %q", got)
	}
	_ = m.Sweep(ctx, t0.Add(62*time.Minute))
	if got := due(t, st); len(got) != 0 {
		t.Fatalf("I10 announced twice: %q", got)
	}

	// I11 reminder on repeat routes only, then again after another period
	_ = m.Sweep(ctx, t0.Add(5*time.Hour+2*time.Minute))
	got = due(t, st)
	if len(got) != 1 || !strings.HasPrefix(got[0], "all|[STILL OPEN 5h02m] uat/h1 #1") {
		t.Fatalf("I11 reminder: %q", got)
	}
	_ = m.Sweep(ctx, t0.Add(6*time.Hour))
	if got := due(t, st); len(got) != 0 {
		t.Fatalf("I11 reminder too early: %q", got)
	}

	// I12 resolved during a silence it never announced: nothing sent
	_, _ = st.AddSilence(ctx, store.Silence{Rule: "disk", Starts: t0, Ends: t0.Add(24 * time.Hour), Created: t0})
	_ = m.Handle(ctx, []rules.Transition{open("disk", "h2")}, t0.Add(7*time.Hour))
	_ = m.Handle(ctx, []rules.Transition{resolve("disk", "h2")}, t0.Add(8*time.Hour))
	if got := due(t, st); len(got) != 0 {
		t.Fatalf("I12 silent resolve: %q", got)
	}

	// I13 weekly maintenance window past midnight (UTC); h1 incident resolves to the routes that heard of it
	night := time.Date(2026, 10, 3, 0, 30, 0, 0, time.UTC)
	_ = m.Handle(ctx, []rules.Transition{open("cpu", "db1")}, night)
	if got := due(t, st); len(got) != 0 {
		t.Fatalf("I13 maintenance: %q", got)
	}
	_ = m.Sweep(ctx, night.Add(31*time.Minute))
	if got := strings.Join(due(t, st), "\n"); strings.Count(got, "uat/db1 #3: cpu high (open since 31m)") != 2 || !strings.Contains(got, "STILL OPEN 13h01m] uat/h1") {
		t.Fatalf("I13 after window (+ due reminder of h1): %q", got)
	}
	_ = m.Handle(ctx, []rules.Transition{resolve("cpu", "h1")}, night)
	if got := due(t, st); len(got) != 2 || !strings.Contains(got[0], "RESOLVED") {
		t.Fatalf("I14 resolved to announced routes: %q", got)
	}
}
