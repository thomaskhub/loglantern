// Package incident turns rule transitions into stored incidents and outbox messages.
package incident

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/hosts"
	"github.com/thomkin/loglantern/internal/rules"
	"github.com/thomkin/loglantern/internal/store"
)

// HostRule is the rule name used for missing hosts.
const HostRule = "host-missing"

// Enricher adds an AI explanation to a new incident (optional).
type Enricher func(ctx context.Context, in store.Incident) (string, error)

// Manager opens and resolves incidents and queues their messages.
type Manager struct {
	st      *store.Store
	routes  []config.Route
	service map[string]string // rule -> service of its matcher
	roleOf  func(env, host string) string
	enrich  Enricher
	log     *slog.Logger
	bg      chan struct{} // limits concurrent enrichments
}

// New creates a manager. enrich may be nil.
func New(st *store.Store, cfg *config.Config, roleOf func(env, host string) string, enrich Enricher, log *slog.Logger) *Manager {
	m := &Manager{st: st, routes: cfg.Routes, service: map[string]string{}, roleOf: roleOf, enrich: enrich, log: log, bg: make(chan struct{}, 2)}
	for _, r := range cfg.Rules {
		m.service[r.Name] = r.Match.Service
	}
	if m.roleOf == nil {
		m.roleOf = func(string, string) string { return "" }
	}
	return m
}

// HostTransitions converts heartbeat changes into transitions.
func HostTransitions(changes []hosts.Change) []rules.Transition {
	out := make([]rules.Transition, 0, len(changes))
	for _, c := range changes {
		t := rules.Transition{Key: HostRule + "/" + c.Env + "/" + c.Host, Rule: HostRule, Env: c.Env, Host: c.Host, Severity: "critical", Open: c.Missing}
		if c.Missing {
			last := "never"
			if c.LastSeen != nil {
				last = c.LastSeen.UTC().Format("2006-01-02 15:04 UTC")
			}
			t.Text = fmt.Sprintf("%s (%s) sends no data, last seen %s", c.Host, c.Env, last)
		} else {
			t.Text = fmt.Sprintf("%s (%s) sends data again", c.Host, c.Env)
		}
		out = append(out, t)
	}
	return out
}

// Handle stores transitions and queues one message per matching route.
func (m *Manager) Handle(ctx context.Context, ts []rules.Transition, now time.Time) error {
	for _, t := range ts {
		if t.Open {
			in := store.Incident{Key: t.Key, Rule: t.Rule, Env: t.Env, Host: t.Host, Severity: t.Severity, Opened: now, Text: t.Text}
			id, ok, err := m.st.OpenIncident(ctx, in)
			if err != nil {
				return fmt.Errorf("open %s: %w", t.Key, err)
			}
			if !ok {
				continue // already open (e.g. after a restart)
			}
			in.ID = id
			if err := m.queue(ctx, t, id, OpenText(in), now); err != nil {
				return err
			}
			if m.enrich != nil {
				m.followUp(in, t)
			}
			continue
		}
		in, ok, err := m.st.ResolveIncident(ctx, t.Key, now)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", t.Key, err)
		}
		if !ok {
			continue
		}
		if t.Text != "" && t.Rule == HostRule {
			in.Text = t.Text
		}
		if err := m.queue(ctx, t, in.ID, ResolvedText(in, now), now); err != nil {
			return err
		}
	}
	return nil
}

// Routes returns the names of the routes that match a transition.
func (m *Manager) Routes(t rules.Transition) []string {
	var out []string
	role := m.roleOf(t.Env, t.Host)
	for _, r := range m.routes {
		mt := r.Match
		if (mt.Env == "" || mt.Env == t.Env) && (mt.Host == "" || mt.Host == t.Host) && (mt.Role == "" || mt.Role == role) &&
			(mt.Service == "" || mt.Service == m.service[t.Rule]) && (len(mt.Severity) == 0 || slices.Contains(mt.Severity, t.Severity)) {
			out = append(out, r.Name)
		}
	}
	return out
}

func (m *Manager) queue(ctx context.Context, t rules.Transition, id int64, text string, now time.Time) error {
	routes := m.Routes(t)
	if len(routes) == 0 {
		m.log.Debug("no route", "key", t.Key)
	}
	for _, r := range routes {
		if err := m.st.Enqueue(ctx, r, text, id, now); err != nil {
			return fmt.Errorf("enqueue %s: %w", r, err)
		}
	}
	return nil
}

// followUp asks the enricher in the background and sends its answer as a second message.
func (m *Manager) followUp(in store.Incident, t rules.Transition) {
	select {
	case m.bg <- struct{}{}:
	default:
		m.log.Warn("ai busy, skipped", "incident", in.ID)
		return
	}
	go func() {
		defer func() { <-m.bg }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		text, err := m.enrich(ctx, in)
		if err != nil || strings.TrimSpace(text) == "" {
			if err != nil {
				m.log.Warn("ai enrichment", "incident", in.ID, "err", err)
			}
			return
		}
		if err := m.st.SetAIText(ctx, in.ID, text); err != nil {
			m.log.Warn("ai text", "err", err)
			return
		}
		if err := m.queue(ctx, t, in.ID, fmt.Sprintf("[AI] %s/%s #%d: %s", in.Env, in.Host, in.ID, text), time.Now()); err != nil {
			m.log.Warn("ai message", "err", err)
		}
	}()
}

// Wait blocks until running enrichments are done (tests, shutdown).
func (m *Manager) Wait() {
	for range cap(m.bg) {
		m.bg <- struct{}{}
	}
	for range cap(m.bg) {
		<-m.bg
	}
}

// OpenText is the message for a new incident.
func OpenText(in store.Incident) string {
	return fmt.Sprintf("[%s] %s/%s #%d: %s", strings.ToUpper(in.Severity), in.Env, in.Host, in.ID, in.Text)
}

// ResolvedText is the message for a resolved incident.
func ResolvedText(in store.Incident, now time.Time) string {
	return fmt.Sprintf("[RESOLVED] %s/%s #%d after %s: %s", in.Env, in.Host, in.ID, Short(now.Sub(in.Opened)), in.Text)
}

// Short formats a duration as 45s, 12m, 3h05m or 2d04h.
func Short(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
}
