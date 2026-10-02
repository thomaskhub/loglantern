// Package incident turns rule transitions into stored incidents and outbox messages.
package incident

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/hosts"
	"github.com/thomaskhub/loglantern/internal/notify"
	"github.com/thomaskhub/loglantern/internal/rules"
	"github.com/thomaskhub/loglantern/internal/store"
)

// HostRule is the rule name used for missing hosts.
const HostRule = "host-missing"

// Note is one AI answer about an incident.
type Note struct {
	Agent, Text string
	Route       string // "" = the incident's routes
}

// Enricher runs the AI agents for a new incident (optional). role and service are the incident's labels.
type Enricher func(ctx context.Context, in store.Incident, role, service string) ([]Note, error)

// Manager opens and resolves incidents and queues their messages.
type Manager struct {
	st          *store.Store
	out         *notify.Outbox
	routes      []config.Route
	byName      map[string]config.Route
	maintenance []config.Maintenance
	service     map[string]string // rule -> service of its matcher
	roleOf      func(env, host string) string
	enrich      Enricher
	log         *slog.Logger
	bg          chan struct{} // limits concurrent enrichments
}

// New creates a manager. enrich may be nil.
func New(st *store.Store, cfg *config.Config, roleOf func(env, host string) string, enrich Enricher, log *slog.Logger) *Manager {
	m := &Manager{st: st, out: notify.NewOutbox(st, cfg), routes: cfg.Routes, service: map[string]string{}, roleOf: roleOf, enrich: enrich, log: log, bg: make(chan struct{}, 2)}
	for _, r := range cfg.Rules {
		m.service[r.Name] = r.Match.Service
	}
	m.byName = map[string]config.Route{}
	for _, r := range cfg.Routes {
		m.byName[r.Name] = r
	}
	m.maintenance = cfg.Maintenance
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

// Handle stores transitions. A new incident is announced on every matching route unless it is silenced
// (Sweep announces it once the silence ends); a resolved incident is announced where it was announced before.
func (m *Manager) Handle(ctx context.Context, ts []rules.Transition, now time.Time) error {
	sil, err := m.st.Silences(ctx, now)
	if err != nil {
		return fmt.Errorf("silences: %w", err)
	}
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
			if m.Silenced(t, sil, now) {
				m.log.Info("incident silenced", "id", id, "key", t.Key)
				continue
			}
			if err := m.announce(ctx, in, t, nil, now); err != nil {
				return err
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
		told, err := m.st.Notified(ctx, in.ID)
		if err != nil {
			return err
		}
		for _, r := range m.Routes(t) {
			if _, ok := told[r]; !ok {
				continue // never announced there (silenced, or route added later)
			}
			if err := m.out.Put(ctx, r, ResolvedText(in, now), in.ID, true, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// announce sends the opening message to the routes that have not had it yet and starts the AI follow-up.
func (m *Manager) announce(ctx context.Context, in store.Incident, t rules.Transition, told map[string]time.Time, now time.Time) error {
	sent := false
	for _, r := range m.Routes(t) {
		if _, ok := told[r]; ok {
			continue
		}
		text := OpenText(in)
		if now.Sub(in.Opened) > time.Minute {
			text = fmt.Sprintf("%s (open since %s)", text, Short(now.Sub(in.Opened)))
		}
		if err := m.out.Put(ctx, r, text, in.ID, false, now); err != nil {
			return err
		}
		if err := m.st.MarkNotified(ctx, in.ID, r, now); err != nil {
			return err
		}
		sent = true
	}
	if sent && m.enrich != nil && in.AIText == "" && len(told) == 0 {
		m.followUp(in, t) // first announcement, also when it comes late after a silence
	}
	return nil
}

// Sweep announces open incidents whose silence has ended and sends reminders on routes with repeat.
func (m *Manager) Sweep(ctx context.Context, now time.Time) error {
	open, err := m.st.Incidents(ctx, store.IncidentFilter{Status: store.StatusOpen, Limit: 10000})
	if err != nil {
		return err
	}
	if len(open) == 0 {
		return nil
	}
	sil, err := m.st.Silences(ctx, now)
	if err != nil {
		return err
	}
	for _, in := range open {
		t := rules.Transition{Key: in.Key, Rule: in.Rule, Env: in.Env, Host: in.Host, Severity: in.Severity, Open: true, Text: in.Text}
		if m.Silenced(t, sil, now) {
			continue
		}
		told, err := m.st.Notified(ctx, in.ID)
		if err != nil {
			return err
		}
		if err := m.announce(ctx, in, t, told, now); err != nil {
			return err
		}
		for _, r := range m.Routes(t) {
			last, ok := told[r]
			rep := time.Duration(m.byName[r].Repeat)
			if !ok || rep <= 0 || now.Sub(last) < rep {
				continue
			}
			text := fmt.Sprintf("[STILL OPEN %s] %s/%s #%d: %s", Short(now.Sub(in.Opened)), in.Env, in.Host, in.ID, in.Text)
			if err := m.out.Put(ctx, r, text, in.ID, false, now); err != nil {
				return err
			}
			if err := m.st.MarkNotified(ctx, in.ID, r, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// Silenced reports whether a maintenance window or a stored silence covers the incident.
func (m *Manager) Silenced(t rules.Transition, sil []store.Silence, now time.Time) bool {
	role, service := m.roleOf(t.Env, t.Host), m.service[t.Rule]
	for _, w := range m.maintenance {
		if (w.Rule == "" || w.Rule == t.Rule) && w.Match.Fits(t.Env, t.Host, role, service, t.Severity) && w.Active(now) {
			return true
		}
	}
	for _, x := range sil {
		mt := config.Match{Env: x.Env, Host: x.Host, Role: x.Role, Service: x.Service, Severity: x.Severity}
		if !now.Before(x.Starts) && now.Before(x.Ends) && (x.Rule == "" || x.Rule == t.Rule) && mt.Fits(t.Env, t.Host, role, service, t.Severity) {
			return true
		}
	}
	return false
}

// Routes returns the names of the routes that match a transition.
func (m *Manager) Routes(t rules.Transition) []string {
	var out []string
	role := m.roleOf(t.Env, t.Host)
	for _, r := range m.routes {
		if r.Match.Fits(t.Env, t.Host, role, m.service[t.Rule], t.Severity) {
			out = append(out, r.Name)
		}
	}
	return out
}

func (m *Manager) queue(ctx context.Context, t rules.Transition, id int64, text string, resolved bool, now time.Time) error {
	for _, r := range m.Routes(t) {
		if err := m.out.Put(ctx, r, text, id, resolved, now); err != nil {
			return err
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
		notes, err := m.enrich(ctx, in, m.roleOf(in.Env, in.Host), m.service[in.Rule])
		if err != nil {
			m.log.Warn("ai enrichment", "incident", in.ID, "err", err)
		}
		var stored []string
		for _, n := range notes {
			if strings.TrimSpace(n.Text) == "" {
				continue
			}
			stored = append(stored, n.Agent+": "+n.Text)
			msg := fmt.Sprintf("[AI %s] %s/%s #%d: %s", n.Agent, in.Env, in.Host, in.ID, n.Text)
			var err error
			if n.Route != "" {
				err = m.out.Put(ctx, n.Route, msg, in.ID, false, time.Now())
			} else {
				err = m.queue(ctx, t, in.ID, msg, false, time.Now())
			}
			if err != nil {
				m.log.Warn("ai message", "err", err)
			}
		}
		if len(stored) > 0 {
			if err := m.st.SetAIText(ctx, in.ID, strings.Join(stored, "\n\n")); err != nil {
				m.log.Warn("ai text", "err", err)
			}
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
