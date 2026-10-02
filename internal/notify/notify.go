// Package notify delivers outbox messages to Telegram and webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/store"
)

// Notifier sends one text to a target (e.g. a Telegram topic name).
type Notifier interface {
	Send(ctx context.Context, target, text string) error
}

// RetryAfter is returned when the receiver asks to wait.
type RetryAfter struct {
	Wait time.Duration
	Err  error
}

func (e *RetryAfter) Error() string { return fmt.Sprintf("%v (retry after %s)", e.Err, e.Wait) }

// maxText is Telegram's message limit; webhooks get the same cut.
const maxText = 4096

func cut(s string) string {
	if len(s) <= maxText {
		return s
	}
	r := []rune(s)
	for len(string(r)) > maxText-1 {
		r = r[:len(r)-100]
	}
	return string(r) + "…"
}

// Telegram sends with the Bot API; targets map to forum topics.
type Telegram struct {
	Base   string // https://api.telegram.org
	Token  string
	ChatID string
	Topics map[string]int
	Client *http.Client
}

// Send posts a plain text message.
func (t *Telegram) Send(ctx context.Context, target, text string) error {
	body := map[string]any{"chat_id": t.ChatID, "text": cut(text), "disable_web_page_preview": true}
	if target != "" {
		id, ok := t.Topics[target]
		if !ok {
			return fmt.Errorf("telegram: unknown topic %q", target)
		}
		body["message_thread_id"] = id
	}
	resp, err := post(ctx, t.Client, strings.TrimRight(t.Base, "/")+"/bot"+t.Token+"/sendMessage", body)
	if err != nil {
		return errors.New("telegram: request failed") // the URL holds the token: never log it
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r)
	if resp.StatusCode == http.StatusTooManyRequests && r.Parameters.RetryAfter > 0 {
		return &RetryAfter{Wait: time.Duration(r.Parameters.RetryAfter) * time.Second, Err: errors.New("telegram: rate limited")}
	}
	if resp.StatusCode != http.StatusOK || !r.OK {
		return fmt.Errorf("telegram: %d %s", resp.StatusCode, r.Description)
	}
	return nil
}

// Webhook posts {"text", "target"} as JSON.
type Webhook struct {
	URL    string
	Client *http.Client
}

// Send posts the message.
func (w *Webhook) Send(ctx context.Context, target, text string) error {
	resp, err := post(ctx, w.Client, w.URL, map[string]string{"text": cut(text), "target": target})
	if err != nil {
		return errors.New("webhook: request failed") // the URL may hold a secret
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusTooManyRequests {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			return &RetryAfter{Wait: time.Duration(s) * time.Second, Err: errors.New("webhook: rate limited")}
		}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: status %d", resp.StatusCode)
	}
	return nil
}

func post(ctx context.Context, c *http.Client, url string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c == nil {
		c = http.DefaultClient
	}
	return c.Do(req)
}

// FromConfig builds the configured notifiers by name ("telegram", "webhook").
func FromConfig(cfg *config.Config) map[string]Notifier {
	client := &http.Client{Timeout: 15 * time.Second}
	out := map[string]Notifier{}
	if t := cfg.Notifiers.Telegram; t != nil {
		base := t.BaseURL
		if base == "" {
			base = "https://api.telegram.org"
		}
		out["telegram"] = &Telegram{Base: base, Token: cfg.Secret(t.TokenEnv), ChatID: t.ChatID, Topics: t.Topics, Client: client}
	}
	if w := cfg.Notifiers.Webhook; w != nil {
		out["webhook"] = &Webhook{URL: cfg.Secret(w.URLEnv), Client: client}
	}
	return out
}

// Sender delivers due outbox messages with exponential backoff.
type Sender struct {
	Store     *store.Store
	Routes    map[string]config.Route
	Notifiers map[string]Notifier
	Log       *slog.Logger
	Every     time.Duration // poll interval (default 5s)
	Now       func() time.Time
}

// NewSender wires a sender from config.
func NewSender(st *store.Store, cfg *config.Config, n map[string]Notifier, log *slog.Logger) *Sender {
	routes := map[string]config.Route{}
	for _, r := range cfg.Routes {
		routes[r.Name] = r
	}
	return &Sender{Store: st, Routes: routes, Notifiers: n, Log: log}
}

// Backoff after n failed attempts: 30s, 1m, 2m … capped at 30m.
func Backoff(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 0; i < attempts && d < 30*time.Minute; i++ {
		d *= 2
	}
	return min(d, 30*time.Minute)
}

// Run polls until ctx ends; wake triggers an immediate round.
func (s *Sender) Run(ctx context.Context, wake <-chan struct{}) {
	every := s.Every
	if every == 0 {
		every = 5 * time.Second
	}
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		s.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		case <-wake:
		}
	}
}

// Once sends everything due now; returns the number delivered.
func (s *Sender) Once(ctx context.Context) int {
	now := s.now()
	msgs, err := s.Store.Due(ctx, now, 50)
	if err != nil {
		s.Log.Error("outbox", "err", err)
		return 0
	}
	sent := 0
	for _, m := range msgs {
		err := s.send(ctx, m)
		if err == nil {
			if err := s.Store.MarkSent(ctx, m.ID, s.now()); err != nil {
				s.Log.Error("outbox mark sent", "id", m.ID, "err", err)
			}
			sent++
			continue
		}
		wait := Backoff(m.Attempts)
		var ra *RetryAfter
		if errors.As(err, &ra) {
			wait = max(ra.Wait, time.Second)
		}
		s.Log.Warn("send failed", "id", m.ID, "route", m.Route, "attempt", m.Attempts+1, "retry_in", wait, "err", err)
		if err := s.Store.MarkFailed(ctx, m.ID, now.Add(wait), err.Error()); err != nil {
			s.Log.Error("outbox mark failed", "id", m.ID, "err", err)
		}
		if ra != nil {
			break // receiver throttles: stop this round
		}
	}
	return sent
}

func (s *Sender) send(ctx context.Context, m store.Message) error {
	r, ok := s.Routes[m.Route]
	if !ok {
		return fmt.Errorf("route %q no longer configured", m.Route)
	}
	n, ok := s.Notifiers[r.Notifier]
	if !ok {
		return fmt.Errorf("notifier %q not configured", r.Notifier)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return n.Send(ctx, r.Target, m.Text)
}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
