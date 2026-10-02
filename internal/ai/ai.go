// Package ai adds a short explanation to new incidents with an OpenAI-compatible chat API (e.g. OpenRouter).
// It never decides alarms: rules do. Off unless configured.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/store"
)

// ErrBudget is returned when the daily call budget is used up.
var ErrBudget = errors.New("ai: daily budget used up")

// Client calls the chat completions endpoint.
type Client struct {
	base, model, key string
	maxTokens       int
	daily           int
	extra           map[string]any
	http            *http.Client
	Now             func() time.Time

	mu    sync.Mutex
	day   string
	calls int
}

// New builds a client from config (cfg.AIEnabled() must be true).
func New(cfg *config.Config) *Client {
	a := cfg.AI
	return &Client{base: strings.TrimRight(a.BaseURL, "/"), model: a.Model, key: cfg.Secret(a.KeyEnv), maxTokens: a.MaxTokens,
		daily: a.DailyCalls, extra: a.Extra, http: &http.Client{Timeout: time.Duration(a.Timeout)}, Now: time.Now}
}

// take reserves one call of today's budget.
func (c *Client) take() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.Now().UTC().Format("2006-01-02"); d != c.day {
		c.day, c.calls = d, 0
	}
	if c.calls >= c.daily {
		return false
	}
	c.calls++
	return true
}

// Ask sends a system and a user message and returns the answer text.
func (c *Client) Ask(ctx context.Context, system, user string) (string, error) {
	if !c.take() {
		return "", ErrBudget
	}
	body := map[string]any{}
	maps.Copy(body, c.extra)
	body["model"] = c.model
	body["max_tokens"] = c.maxTokens
	body["messages"] = []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("X-Title", "loglantern")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: %w", err)
	}
	defer resp.Body.Close()
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", fmt.Errorf("ai: status %d: %w", resp.StatusCode, err)
	}
	if r.Error != nil {
		return "", fmt.Errorf("ai: status %d: %s", resp.StatusCode, r.Error.Message)
	}
	if resp.StatusCode != http.StatusOK || len(r.Choices) == 0 {
		return "", fmt.Errorf("ai: status %d, no answer", resp.StatusCode)
	}
	return strings.TrimSpace(r.Choices[0].Message.Content), nil
}

var (
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	secretRe = regexp.MustCompile(`(?i)(bearer\s+|token[=:]\s*|password[=:]\s*|secret[=:]\s*|key[=:]\s*)\S+`)
	jwtRe    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
)

// Mask removes e-mail addresses and obvious secrets before text leaves the server.
func Mask(s string) string {
	s = jwtRe.ReplaceAllString(s, "<jwt>")
	s = secretRe.ReplaceAllString(s, "${1}<secret>")
	return emailRe.ReplaceAllString(s, "<email>")
}

const system = `You help an operator understand a server alert. Answer in at most 3 short sentences of plain text: ` +
	`the likely cause and the first thing to check. Do not repeat the alert. If the context is not enough, say so briefly.`

// Enricher returns an incident enricher that adds recent log lines and last values of the host as context.
func Enricher(c *Client, st *store.Store) func(ctx context.Context, in store.Incident) (string, error) {
	return func(ctx context.Context, in store.Incident) (string, error) {
		var b strings.Builder
		fmt.Fprintf(&b, "Alert (%s): %s\nRule: %s, host %s, environment %s, opened %s\n", in.Severity, in.Text, in.Rule, in.Host, in.Env, in.Opened.UTC().Format(time.RFC3339))
		if hs, err := st.Hosts(ctx, []string{in.Env}); err == nil {
			for _, h := range hs {
				if h.Host != in.Host || len(h.Last) == 0 {
					continue
				}
				b.WriteString("\nLast values:\n")
				for _, k := range slices.Sorted(maps.Keys(h.Last)) {
					fmt.Fprintf(&b, "%s=%g\n", k, h.Last[k])
				}
			}
		}
		lines, _, err := st.Logs(ctx, store.LogFilter{Envs: []string{in.Env}, Host: in.Host, MaxLevel: 4, From: in.Opened.Add(-30 * time.Minute), To: in.Opened.Add(time.Minute), Limit: 20})
		if err == nil && len(lines) > 0 {
			b.WriteString("\nRecent warnings and errors (newest first):\n")
			for _, l := range lines {
				msg := l.Message
				if len(msg) > 300 {
					msg = msg[:300] + "…"
				}
				fmt.Fprintf(&b, "%s %s: %s\n", l.TS.UTC().Format("15:04:05"), l.Service, msg)
			}
		}
		return c.Ask(ctx, system, Mask(b.String()))
	}
}
