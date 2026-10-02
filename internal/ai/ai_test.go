package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
	"github.com/thomaskhub/loglantern/internal/store"
)

func TestAskBudgetMask(t *testing.T) {
	var last map[string]any
	var auth string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&last)
		if fail {
			w.WriteHeader(402)
			_, _ = io.WriteString(w, `{"error":{"message":"no credits"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"  disk full on /var  "}}]}`)
	}))
	defer srv.Close()
	cfg := &config.Config{AI: &config.AI{BaseURL: srv.URL + "/", KeyEnv: "K", DailyCalls: 2, Timeout: config.Duration(5 * time.Second),
		Extra: map[string]any{"reasoning": map[string]any{"effort": "none"}, "model": "must-not-win", "temperature": 1}}, Secrets: map[string]string{"K": "sk-1"}}
	c := New(cfg)
	day := time.Date(2026, 10, 2, 23, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return day }
	ctx := context.Background()

	call := Call{Model: "m1", MaxTokens: 50, Extra: map[string]any{"temperature": 0.2}, System: "sys", User: "user"}
	got, err := c.Ask(ctx, call)
	if err != nil || got != "disk full on /var" {
		t.Fatalf("A1: %q %v", got, err)
	}
	if auth != "Bearer sk-1" || last["model"] != "m1" || last["max_tokens"] != float64(50) || last["reasoning"] == nil || last["temperature"] != 0.2 {
		t.Fatalf("A2 request: %v", last)
	}
	fail = true
	if _, err := c.Ask(ctx, call); err == nil || !strings.Contains(err.Error(), "no credits") {
		t.Fatalf("A3 api error: %v", err)
	}
	if _, err := c.Ask(ctx, call); err != ErrBudget {
		t.Fatalf("A4 budget: %v", err)
	}
	fail = false
	day = day.Add(2 * time.Hour) // next UTC day
	if _, err := c.Ask(ctx, call); err != nil {
		t.Fatalf("A4 budget resets per day: %v", err)
	}

	in := "user a.b@x.org failed, Authorization: Bearer abc.def token=xyz password: hunter2 eyJhbGciOi.eyJzdWIi.sig"
	m := Mask(in)
	for _, leak := range []string{"a.b@x.org", "abc.def", "xyz", "hunter2", "eyJhbGciOi"} {
		if strings.Contains(m, leak) {
			t.Errorf("A5 mask leaks %q: %s", leak, m)
		}
	}
}

type fakeAPI struct {
	calls []struct{ Model, System, User string }
}

func (f *fakeAPI) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Model    string
			Messages []struct{ Content string } `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.calls = append(f.calls, struct{ Model, System, User string }{b.Model, b.Messages[0].Content, b.Messages[1].Content})
		if b.Model == "broken" {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"error":{"message":"overloaded"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"answer from `+b.Model+`"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAgents(t *testing.T) {
	f := &fakeAPI{}
	srv := f.server(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "dba.md"), []byte("\nYou are a careful DBA.\n"), 0o644)
	t.Setenv("LL_T", "t")
	t.Setenv("LL_AI", "k")
	cfgPath := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(cfgPath, []byte(`
storage: {path: `+filepath.Join(dir, "x.db")+`}
envs: {uat: {ingest_token_env: LL_T}}
routes: [{name: all, send: [hook]}, {name: dba, send: [hook]}]
notifiers: {hook: {webhook: {url_env: LL_T}}}
ai:
  base_url: `+srv.URL+`
  key_env: LL_AI
  model: small
  agents:
    - {name: explain, on: incident_open}
    - {name: dba, on: incident_open, match: {role: db}, model: big, prompt_file: dba.md, route: dba, context: {logs: -1, values: false}}
    - {name: crit, on: incident_open, match: {severity: [critical]}, model: broken, prompt: "x"}
    - {name: review, on: daily_report, prompt: "Pick 3 things to act on."}
`), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	_ = st.Write(ctx, []record.Record{
		{Kind: record.KindLog, TS: t0.Add(-5 * time.Minute), Env: "uat", Host: "h1", Service: "api", Level: 3, Message: "db timeout for x@y.com"},
		{Kind: record.KindLog, TS: t0.Add(-4 * time.Minute), Env: "uat", Host: "h1", Service: "api", Level: 6, Message: "info noise"},
		{Kind: record.KindLog, TS: t0.Add(-4 * time.Minute), Env: "uat", Host: "h2", Service: "api", Level: 3, Message: "other host"},
		{Kind: record.KindLog, TS: t0.Add(-2 * time.Hour), Env: "uat", Host: "h1", Service: "api", Level: 3, Message: "too old"},
	})
	_ = st.SaveHosts(ctx, []store.Host{{Env: "uat", Host: "h1", Status: "up", Last: map[string]float64{"cpu.cpu_p": 97}}})
	ag := NewAgents(cfg, st)
	in := store.Incident{Rule: "cpu", Env: "uat", Host: "h1", Severity: "warning", Opened: t0, Text: "cpu high"}

	// G1 default agent: default prompt, ai.model, values + warnings of the host, masked
	notes, err := ag.Incident(ctx, in, "api", "")
	if err != nil || len(notes) != 1 || notes[0].Agent != "explain" || notes[0].Text != "answer from small" || notes[0].Route != "" {
		t.Fatalf("G1: %+v %v", notes, err)
	}
	c := f.calls[0]
	if c.System != config.DefaultAgentPrompt || c.Model != "small" {
		t.Fatalf("G1 call: %+v", c)
	}
	for _, want := range []string{"cpu high", "cpu.cpu_p=97", "db timeout for <email>", "warning or worse"} {
		if !strings.Contains(c.User, want) {
			t.Errorf("G1 context lacks %q:\n%s", want, c.User)
		}
	}
	for _, not := range []string{"info noise", "other host", "x@y.com", "too old"} {
		if strings.Contains(c.User, not) {
			t.Errorf("G1 context has %q", not)
		}
	}

	// G2 role match, own model, prompt file (trimmed, relative to config), own route, no logs/values
	f.calls = nil
	notes, _ = ag.Incident(ctx, in, "db", "")
	if len(notes) != 2 || notes[1].Agent != "dba" || notes[1].Route != "dba" || notes[1].Text != "answer from big" {
		t.Fatalf("G2: %+v", notes)
	}
	if c := f.calls[1]; c.System != "You are a careful DBA." || strings.Contains(c.User, "cpu.cpu_p") || strings.Contains(c.User, "timeout") {
		t.Fatalf("G2 call: %+v", c)
	}

	// G3 a failing agent does not stop the others
	in.Severity = "critical"
	notes, err = ag.Incident(ctx, in, "api", "")
	if len(notes) != 1 || err == nil || !strings.Contains(err.Error(), "agent crit") {
		t.Fatalf("G3: %+v %v", notes, err)
	}

	// G4 report agent gets the report text
	f.calls = nil
	notes, err = ag.Report(ctx, "Daily report\nUAT: 2 hosts")
	if err != nil || len(notes) != 1 || notes[0].Agent != "review" || f.calls[0].User != "Daily report\nUAT: 2 hosts" || f.calls[0].System != "Pick 3 things to act on." {
		t.Fatalf("G4: %+v %v %+v", notes, err, f.calls)
	}
	if !ag.Has(config.OnDailyReport) || !ag.Has(config.OnIncidentOpen) {
		t.Fatal("G5 Has")
	}
}
