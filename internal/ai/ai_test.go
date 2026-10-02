package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/record"
	"github.com/thomkin/loglantern/internal/store"
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
	cfg := &config.Config{AI: &config.AI{BaseURL: srv.URL + "/", Model: "m1", KeyEnv: "K", DailyCalls: 2, MaxTokens: 50, Timeout: config.Duration(5 * time.Second),
		Extra: map[string]any{"reasoning": map[string]any{"effort": "none"}, "model": "must-not-win"}}, Secrets: map[string]string{"K": "sk-1"}}
	c := New(cfg)
	day := time.Date(2026, 10, 2, 23, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return day }
	ctx := context.Background()

	got, err := c.Ask(ctx, "sys", "user")
	if err != nil || got != "disk full on /var" {
		t.Fatalf("A1: %q %v", got, err)
	}
	if auth != "Bearer sk-1" || last["model"] != "m1" || last["max_tokens"] != float64(50) || last["reasoning"] == nil {
		t.Fatalf("A2 request: %v", last)
	}
	fail = true
	if _, err := c.Ask(ctx, "s", "u"); err == nil || !strings.Contains(err.Error(), "no credits") {
		t.Fatalf("A3 api error: %v", err)
	}
	if _, err := c.Ask(ctx, "s", "u"); err != ErrBudget {
		t.Fatalf("A4 budget: %v", err)
	}
	fail = false
	day = day.Add(2 * time.Hour) // next UTC day
	if _, err := c.Ask(ctx, "s", "u"); err != nil {
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

func TestEnricherContext(t *testing.T) {
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		prompt = b.Messages[1].Content
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
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
	})
	_ = st.SaveHosts(ctx, []store.Host{{Env: "uat", Host: "h1", Status: "up", Last: map[string]float64{"cpu.cpu_p": 97}}})
	cfg := &config.Config{AI: &config.AI{BaseURL: srv.URL, Model: "m", KeyEnv: "K", DailyCalls: 5, MaxTokens: 10, Timeout: config.Duration(time.Second)}, Secrets: map[string]string{"K": "k"}}
	e := Enricher(New(cfg), st)
	if _, err := e(ctx, store.Incident{Rule: "cpu", Env: "uat", Host: "h1", Severity: "warning", Opened: t0, Text: "cpu high"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cpu high", "cpu.cpu_p=97", "db timeout for <email>"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("A6 prompt lacks %q:\n%s", want, prompt)
		}
	}
	for _, not := range []string{"info noise", "other host", "x@y.com"} {
		if strings.Contains(prompt, not) {
			t.Errorf("A6 prompt has %q", not)
		}
	}
}
