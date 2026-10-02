// Package report builds and queues the daily summary.
package report

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/thomaskhub/loglantern/internal/notify"
	"github.com/thomaskhub/loglantern/internal/store"
)

const metaKey = "report.last"

// Build returns the summary of the 24 hours before now for these envs.
func Build(ctx context.Context, st *store.Store, envs []string, now time.Time) (string, error) {
	slices.Sort(envs)
	since := now.Add(-24 * time.Hour)
	var b strings.Builder
	fmt.Fprintf(&b, "Daily report %s (last 24 h)\n", now.UTC().Format("2006-01-02 15:04 UTC"))
	for _, env := range envs {
		e := []string{env}
		hosts, err := st.Hosts(ctx, e)
		if err != nil {
			return "", err
		}
		var missing []string
		lowBurst := ""
		for _, h := range hosts {
			if h.Status != "up" {
				missing = append(missing, h.Host)
			}
			if v, ok := h.Last["lightsail.burst_pct"]; ok && v < 50 {
				lowBurst += fmt.Sprintf(" %s %.0f%%", h.Host, v)
			}
		}
		fmt.Fprintf(&b, "\n%s: %d hosts, %d up", strings.ToUpper(env), len(hosts), len(hosts)-len(missing))
		if len(missing) > 0 {
			fmt.Fprintf(&b, ", not reporting: %s", strings.Join(missing, ", "))
		}
		b.WriteString("\n")

		ins, err := st.Incidents(ctx, store.IncidentFilter{Envs: e, Since: since, Limit: 1000})
		if err != nil {
			return "", err
		}
		open, err := st.Incidents(ctx, store.IncidentFilter{Envs: e, Status: store.StatusOpen, Limit: 1000})
		if err != nil {
			return "", err
		}
		bySev := map[string]int{}
		byRule := map[string]int{}
		for _, in := range ins {
			bySev[in.Severity]++
			byRule[in.Rule]++
		}
		fmt.Fprintf(&b, "Incidents: %d new (critical %d, warning %d, info %d), %d still open\n", len(ins), bySev["critical"], bySev["warning"], bySev["info"], len(open))
		if top := topN(byRule, 3); top != "" {
			fmt.Fprintf(&b, "Most frequent: %s\n", top)
		}
		for _, in := range open {
			fmt.Fprintf(&b, "  open #%d %s/%s since %s: %s\n", in.ID, in.Rule, in.Host, in.Opened.UTC().Format("01-02 15:04"), clip(in.Text, 120))
		}

		cur, err := errorsBySvc(ctx, st, e, since, now)
		if err != nil {
			return "", err
		}
		prev, err := errorsBySvc(ctx, st, e, since.Add(-24*time.Hour), since)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "Error lines: %d (day before: %d)\n", sum(cur), sum(prev))
		if top := topN(cur, 3); top != "" {
			fmt.Fprintf(&b, "Noisiest: %s\n", top)
		}
		if lowBurst != "" {
			fmt.Fprintf(&b, "Low CPU burst capacity:%s\n", lowBurst)
		}
	}
	return b.String(), nil
}

// errorsBySvc counts lines with level <= 3 (error and worse) per service.
func errorsBySvc(ctx context.Context, st *store.Store, envs []string, from, to time.Time) (map[string]int, error) {
	cs, err := st.Counters(ctx, store.CounterFilter{Envs: envs, From: from, To: to, ByServ: true})
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, c := range cs {
		if c.Level <= 3 {
			out[cmp.Or(c.Service, "-")] += int(c.N)
		}
	}
	return out, nil
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func topN(m map[string]int, n int) string {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int { return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b)) })
	var parts []string
	for _, k := range keys[:min(n, len(keys))] {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// Due reports whether today's report (at "HH:MM" in loc) is due and not yet sent.
func Due(ctx context.Context, st *store.Store, at string, loc *time.Location, now time.Time) (bool, error) {
	t, err := time.Parse("15:04", at)
	if err != nil {
		return false, err
	}
	now = now.In(loc)
	slot := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, loc)
	if now.Before(slot) {
		return false, nil
	}
	last, err := st.Meta(ctx, metaKey)
	if err != nil {
		return false, err
	}
	return last != slot.Format("2006-01-02"), nil
}

// Send builds the report, queues it on route (once per day) and returns its text.
func Send(ctx context.Context, st *store.Store, out *notify.Outbox, envs []string, route string, loc *time.Location, now time.Time) (string, error) {
	text, err := Build(ctx, st, envs, now)
	if err != nil {
		return "", err
	}
	if err := out.Put(ctx, route, text, 0, false, now); err != nil {
		return "", err
	}
	return text, st.SetMeta(ctx, metaKey, now.In(loc).Format("2006-01-02"))
}
