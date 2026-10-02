// Package ai runs the configured agents (one chat call each, no tools) and adds a short explanation to new incidents with an OpenAI-compatible chat API (e.g. OpenRouter).
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
	"github.com/thomkin/loglantern/internal/incident"
	"github.com/thomkin/loglantern/internal/record"
	"github.com/thomkin/loglantern/internal/store"
)

// ErrBudget is returned when the daily call budget is used up.
var ErrBudget = errors.New("ai: daily budget used up")

// Client calls the chat completions endpoint.
type Client struct {
	base, key string
	daily     int
	extra     map[string]any // ai.extra, under each agent's extra
	http      *http.Client
	Now       func() time.Time

	mu    sync.Mutex
	day   string
	calls int
}

// New builds a client from config (cfg.AIEnabled() must be true).
func New(cfg *config.Config) *Client {
	a := cfg.AI
	return &Client{base: strings.TrimRight(a.BaseURL, "/"), key: cfg.Secret(a.KeyEnv),
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

// Call is one request.
type Call struct {
	Model        string
	MaxTokens    int
	Extra        map[string]any
	System, User string
}

// Ask sends a system and a user message and returns the answer text.
func (c *Client) Ask(ctx context.Context, call Call) (string, error) {
	if !c.take() {
		return "", ErrBudget
	}
	body := map[string]any{}
	maps.Copy(body, c.extra)
	maps.Copy(body, call.Extra)
	body["model"] = call.Model
	body["max_tokens"] = call.MaxTokens
	body["messages"] = []map[string]string{{"role": "system", "content": call.System}, {"role": "user", "content": call.User}}
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

// Agents runs the configured agents.
type Agents struct {
	c      *Client
	st     *store.Store
	agents []config.Agent
}

// NewAgents builds the runner (cfg.AIEnabled() must be true).
func NewAgents(cfg *config.Config, st *store.Store) *Agents {
	return &Agents{c: New(cfg), st: st, agents: cfg.AI.Agents}
}

// SetClient replaces the client (tests).
func (a *Agents) SetClient(c *Client) { a.c = c }

// Has reports whether any agent runs on this trigger.
func (a *Agents) Has(on string) bool {
	for _, ag := range a.agents {
		if ag.On == on {
			return true
		}
	}
	return false
}

func (a *Agents) ask(ctx context.Context, ag config.Agent, user string) (string, error) {
	text, err := a.c.Ask(ctx, Call{Model: ag.Model, MaxTokens: ag.MaxTokens, Extra: ag.Extra, System: ag.Prompt, User: Mask(user)})
	if err != nil {
		return "", fmt.Errorf("agent %s: %w", ag.Name, err)
	}
	return text, nil
}

// Incident runs every incident_open agent whose match fits; one note per answer.
func (a *Agents) Incident(ctx context.Context, in store.Incident, role, service string) ([]incident.Note, error) {
	var notes []incident.Note
	var errs []error
	for _, ag := range a.agents {
		if ag.On != config.OnIncidentOpen || !ag.Match.Fits(in.Env, in.Host, role, service, in.Severity) {
			continue
		}
		text, err := a.ask(ctx, ag, a.incidentContext(ctx, ag, in))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		notes = append(notes, incident.Note{Agent: ag.Name, Text: text, Route: ag.Route})
	}
	return notes, errors.Join(errs...)
}

// Report runs every daily_report agent on the report text.
func (a *Agents) Report(ctx context.Context, report string) ([]incident.Note, error) {
	var notes []incident.Note
	var errs []error
	for _, ag := range a.agents {
		if ag.On != config.OnDailyReport {
			continue
		}
		text, err := a.ask(ctx, ag, report)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		notes = append(notes, incident.Note{Agent: ag.Name, Text: text, Route: ag.Route})
	}
	return notes, errors.Join(errs...)
}

// incidentContext is the user message: the alert, and as configured the host's last values and recent log lines.
func (a *Agents) incidentContext(ctx context.Context, ag config.Agent, in store.Incident) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Alert (%s): %s\nRule: %s, host %s, environment %s, opened %s\n", in.Severity, in.Text, in.Rule, in.Host, in.Env, in.Opened.UTC().Format(time.RFC3339))
	if ag.Context.Values == nil || *ag.Context.Values {
		if hs, err := a.st.Hosts(ctx, []string{in.Env}); err == nil {
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
	}
	if ag.Context.Logs > 0 {
		level, _ := record.ParseLevel(ag.Context.Level)
		lines, _, err := a.st.Logs(ctx, store.LogFilter{Envs: []string{in.Env}, Host: in.Host, MaxLevel: level,
			From: in.Opened.Add(-time.Duration(ag.Context.Lookback)), To: in.Opened.Add(time.Minute), Limit: ag.Context.Logs})
		if err == nil && len(lines) > 0 {
			fmt.Fprintf(&b, "\nRecent log lines, %s or worse (newest first):\n", record.LevelNames[level])
			for _, l := range lines {
				msg := l.Message
				if len(msg) > 300 {
					msg = msg[:300] + "…"
				}
				fmt.Fprintf(&b, "%s %s: %s\n", l.TS.UTC().Format("15:04:05"), l.Service, msg)
			}
		}
	}
	return b.String()
}
