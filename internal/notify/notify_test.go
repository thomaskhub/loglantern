package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/store"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func TestTelegram(t *testing.T) {
	var got []map[string]any
	limited := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botTOKEN/sendMessage" {
			w.WriteHeader(404)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["text"] == "slow" && limited {
			limited = false
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":7}}`)
			return
		}
		got = append(got, b)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	tg := &Telegram{Base: srv.URL, Token: "TOKEN", ChatID: "-100", Topics: map[string]int{"db": 42}}
	ctx := context.Background()
	if err := tg.Send(ctx, "db", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := tg.Send(ctx, "", "general"); err != nil {
		t.Fatal(err)
	}
	if got[0]["message_thread_id"] != float64(42) || got[0]["chat_id"] != "-100" || got[1]["message_thread_id"] != nil {
		t.Fatalf("N1 topics: %v", got)
	}
	if err := tg.Send(ctx, "nope", "x"); err == nil {
		t.Fatal("N2 unknown topic accepted")
	}
	var ra *RetryAfter
	if err := tg.Send(ctx, "", "slow"); !errors.As(err, &ra) || ra.Wait != 7*time.Second {
		t.Fatalf("N3 retry_after: %v", err)
	}
	bad := &Telegram{Base: srv.URL, Token: "WRONG", ChatID: "-100"}
	if err := bad.Send(ctx, "", "x"); err == nil || strings.Contains(err.Error(), "WRONG") {
		t.Fatalf("N4 error must not leak token: %v", err)
	}
	if err := (&Telegram{Base: "http://127.0.0.1:1", Token: "SECRET"}).Send(ctx, "", "x"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("N4 transport error leaks token: %v", err)
	}
	long := strings.Repeat("ä", 5000)
	if c := cut(long); len(c) > maxText || !strings.HasSuffix(c, "…") {
		t.Fatalf("N5 cut: %d", len(c))
	}
}

func TestWebhook(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["text"] == "fail" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	w := &Webhook{URL: srv.URL + "/hook?secret=S"}
	if err := w.Send(context.Background(), "ops", "hi"); err != nil || body["text"] != "hi" || body["target"] != "ops" {
		t.Fatalf("N6: %v %v", err, body)
	}
	if err := w.Send(context.Background(), "", "fail"); err == nil {
		t.Fatal("N6 500 accepted")
	}
}

type flaky struct {
	mu    sync.Mutex
	down  bool
	texts []string
}

func (f *flaky) Send(_ context.Context, target, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("down")
	}
	f.texts = append(f.texts, target+"|"+text)
	return nil
}

func TestSenderRetriesExactlyOnce(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	f := &flaky{down: true}
	now := t0
	cfg := &config.Config{Routes: []config.Route{{Name: "all", Notifier: "telegram", Target: "alerts"}, {Name: "gone", Notifier: "pager"}}}
	s := NewSender(st, cfg, map[string]Notifier{"telegram": f}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Now = func() time.Time { return now }
	_ = st.Enqueue(ctx, "all", "one", 0, now)
	_ = st.Enqueue(ctx, "all", "two", 0, now)
	_ = st.Enqueue(ctx, "gone", "x", 0, now)

	if n := s.Once(ctx); n != 0 {
		t.Fatalf("A3 sent while down: %d", n)
	}
	if ms, _ := st.Due(ctx, now.Add(29*time.Second), 10); len(ms) != 0 {
		t.Fatalf("A3 first retry before 30 s backoff: %d due", len(ms))
	}
	now = now.Add(10 * time.Second)
	if n := s.Once(ctx); n != 0 {
		t.Fatal("A3 retried before backoff")
	}
	f.down = false
	now = now.Add(30 * time.Second)
	if n := s.Once(ctx); n != 2 {
		t.Fatalf("A3 after recovery: %d", n)
	}
	now = now.Add(time.Hour)
	s.Once(ctx)
	if strings.Join(f.texts, ",") != "alerts|one,alerts|two" {
		t.Fatalf("A3 exactly once, in order: %v", f.texts)
	}
	if n, _ := st.PendingCount(ctx); n != 1 {
		t.Fatalf("unknown notifier stays pending: %d", n)
	}
}

func TestBackoff(t *testing.T) {
	for a, want := range map[int]time.Duration{0: 30 * time.Second, 1: time.Minute, 3: 4 * time.Minute, 6: 30 * time.Minute, 50: 30 * time.Minute} {
		if got := Backoff(a); got != want {
			t.Errorf("%d: %v", a, got)
		}
	}
}
