// Package rules evaluates the alarm rules on an in-memory window of every series (default 2 h).
// The engine is deterministic and has no I/O: records go in (Observe), transitions come out
// (Evaluate) when a condition has held for the rule's "for" duration (open) or stops (resolve).
package rules

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
)

// stale: a series without a value for this long no longer holds a condition.
const stale = 10 * time.Minute

// Transition is a rule key starting (Open) or stopping to fire.
type Transition struct {
	Key, Rule, Env, Host, Severity string
	Open                           bool
	Text                           string
}

type seriesKey struct{ env, host, name string }

type point struct {
	t time.Time
	v float64
}

type series struct {
	points []point
	text   string
	textT  time.Time
}

type compiled struct {
	config.Rule
	re       *regexp.Regexp
	minLevel int
	num      float64
}

type hitKey struct {
	rule      int
	env, host string
}

type candidate struct {
	env, host string
	value     string
	detail    string
}

// Engine is safe for concurrent use.
type Engine struct {
	mu      sync.Mutex
	rules   []compiled
	window  time.Duration
	roleOf  func(env, host string) string
	series  map[seriesKey]*series
	hits    map[hitKey][]time.Time
	pending map[string]time.Time // key → condition true since
	active  map[string]bool
	seen    map[seriesKey]time.Time // newest value of series watched by absent rules (kept beyond the window)
	started time.Time
	absent  map[string]bool // series names watched by absent rules
}

// New compiles the rules. roleOf resolves a host's role for "match.role".
func New(rules []config.Rule, window time.Duration, roleOf func(env, host string) string) (*Engine, error) {
	e := &Engine{window: window, roleOf: roleOf, series: map[seriesKey]*series{}, hits: map[hitKey][]time.Time{},
		pending: map[string]time.Time{}, active: map[string]bool{}, seen: map[seriesKey]time.Time{}, absent: map[string]bool{}}
	for _, r := range rules {
		c := compiled{Rule: r, minLevel: record.LevelDebug}
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.Name, err)
			}
			c.re = re
		}
		if r.Level != "" {
			l, ok := record.ParseLevel(r.Level)
			if !ok {
				return nil, fmt.Errorf("rule %s: unknown level %q", r.Name, r.Level)
			}
			c.minLevel = l
		}
		if r.Type == config.RuleThreshold {
			v, err := strconv.ParseFloat(r.Value, 64)
			if err != nil {
				return nil, fmt.Errorf("rule %s: value %q is not a number", r.Name, r.Value)
			}
			c.num = v
		}
		if r.Type == config.RuleAbsent {
			e.absent[r.Series] = true
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// ObserveSeen restores when a series watched by an absent rule last had a value (restart).
func (e *Engine) ObserveSeen(env, host, name string, t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.markSeen(seriesKey{env, host, name}, t)
}

// AbsentSeries returns the series names watched by absent rules.
func (e *Engine) AbsentSeries() []string {
	out := make([]string, 0, len(e.absent))
	for n := range e.absent {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) markSeen(k seriesKey, t time.Time) {
	if e.absent[k.name] && t.After(e.seen[k]) {
		e.seen[k] = t
	}
}

// SetActive marks keys as firing (open incidents after a restart) so they can resolve.
func (e *Engine) SetActive(keys []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, k := range keys {
		e.active[k] = true
	}
}

// Observe adds a record to the window.
func (e *Engine) Observe(r record.Record) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, v := range r.Values {
		e.addValue(r.Env, r.Host, name, r.TS, v)
	}
	for name, v := range r.Texts {
		e.addText(r.Env, r.Host, name, r.TS, v)
	}
	if r.Kind == record.KindLog {
		e.addLog(r.Env, r.Host, r.Service, r.Level, r.Message, r.TS)
	}
}

// ObserveValue adds one stored value (window rebuild).
func (e *Engine) ObserveValue(env, host, name string, t time.Time, v float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addValue(env, host, name, t, v)
}

// ObserveText adds one stored text value (window rebuild).
func (e *Engine) ObserveText(env, host, name string, t time.Time, v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addText(env, host, name, t, v)
}

// ObserveLog adds one stored log line (window rebuild).
func (e *Engine) ObserveLog(env, host, service string, level int, msg string, t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addLog(env, host, service, level, msg, t)
}

func (e *Engine) get(env, host, name string) *series {
	k := seriesKey{env, host, name}
	s, ok := e.series[k]
	if !ok {
		s = &series{}
		e.series[k] = s
	}
	return s
}

func (e *Engine) addValue(env, host, name string, t time.Time, v float64) {
	e.markSeen(seriesKey{env, host, name}, t)
	s := e.get(env, host, name)
	if n := len(s.points); n > 0 && t.Before(s.points[n-1].t) {
		i := sort.Search(n, func(i int) bool { return s.points[i].t.After(t) })
		s.points = append(s.points[:i], append([]point{{t, v}}, s.points[i:]...)...)
		return
	}
	s.points = append(s.points, point{t, v})
}

func (e *Engine) addText(env, host, name string, t time.Time, v string) {
	e.markSeen(seriesKey{env, host, name}, t)
	s := e.get(env, host, name)
	if !t.Before(s.textT) {
		s.text, s.textT = v, t
	}
}

func (e *Engine) addLog(env, host, service string, level int, msg string, t time.Time) {
	for i, r := range e.rules {
		if r.Type != config.RuleLogRate || level > r.minLevel {
			continue
		}
		if r.Match.Service != "" && r.Match.Service != service {
			continue
		}
		if r.re != nil && !r.re.MatchString(msg) {
			continue
		}
		k := hitKey{i, env, host}
		e.hits[k] = append(e.hits[k], t)
	}
}

// Evaluate checks every rule at now and returns the transitions.
func (e *Engine) Evaluate(now time.Time) []Transition {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prune(now)
	var out []Transition
	for _, r := range e.rules {
		firing := map[string]candidate{}
		for _, c := range e.candidates(r, now) {
			firing[r.Name+"/"+c.env+"/"+c.host] = c
		}
		for key, c := range firing {
			if e.active[key] {
				continue
			}
			since, ok := e.pending[key]
			if !ok {
				since = now
				e.pending[key] = now
			}
			if now.Sub(since) >= r.For.D() {
				e.active[key] = true
				delete(e.pending, key)
				out = append(out, Transition{Key: key, Rule: r.Name, Env: c.env, Host: c.host, Severity: r.Severity, Open: true, Text: render(r, c)})
			}
		}
		prefix := r.Name + "/"
		for key := range e.pending {
			if strings.HasPrefix(key, prefix) {
				if _, ok := firing[key]; !ok {
					delete(e.pending, key)
				}
			}
		}
		for key := range e.active {
			if strings.HasPrefix(key, prefix) {
				if _, ok := firing[key]; !ok {
					delete(e.active, key)
					parts := strings.SplitN(strings.TrimPrefix(key, prefix), "/", 2)
					t := Transition{Key: key, Rule: r.Name, Severity: r.Severity, Open: false}
					if len(parts) == 2 {
						t.Env, t.Host = parts[0], parts[1]
					}
					out = append(out, t)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (e *Engine) prune(now time.Time) {
	cut := now.Add(-e.window)
	for k, s := range e.series {
		i := sort.Search(len(s.points), func(i int) bool { return !s.points[i].t.Before(cut) })
		s.points = s.points[i:]
		if len(s.points) == 0 && s.textT.Before(cut) {
			delete(e.series, k)
		}
	}
	for k, ts := range e.hits {
		per := e.rules[k.rule].Per.D()
		i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(now.Add(-per)) })
		if i == len(ts) {
			delete(e.hits, k)
		} else {
			e.hits[k] = ts[i:]
		}
	}
}

func (e *Engine) matches(m config.Match, env, host string) bool {
	if m.Env != "" && m.Env != env || m.Host != "" && m.Host != host {
		return false
	}
	return m.Role == "" || (e.roleOf != nil && e.roleOf(env, host) == m.Role)
}

func (e *Engine) candidates(r compiled, now time.Time) []candidate {
	var out []candidate
	switch r.Type {
	case config.RuleThreshold, config.RuleAnomaly:
		for k, s := range e.series {
			if k.name != r.Series || len(s.points) == 0 || !e.matches(r.Match, k.env, k.host) {
				continue
			}
			last := s.points[len(s.points)-1]
			if now.Sub(last.t) > stale {
				continue
			}
			if r.Type == config.RuleThreshold && compare(last.v, r.Op, r.num) {
				out = append(out, candidate{k.env, k.host, num(last.v), fmt.Sprintf("%s %s %s", r.Series, r.Op, r.Value)})
			}
			if r.Type == config.RuleAnomaly {
				if c, ok := anomaly(r, s.points); ok {
					c.env, c.host = k.env, k.host
					out = append(out, c)
				}
			}
		}
	case config.RuleText:
		for k, s := range e.series {
			if k.name != r.Series || s.textT.IsZero() || now.Sub(s.textT) > stale || !e.matches(r.Match, k.env, k.host) {
				continue
			}
			if (r.Op == "==") == (s.text == r.Value) {
				out = append(out, candidate{k.env, k.host, s.text, fmt.Sprintf("%s is %q", r.Series, s.text)})
			}
		}
	case config.RuleAbsent:
		for k, t := range e.seen {
			if k.name != r.Series || !e.matches(r.Match, k.env, k.host) {
				continue
			}
			if age := now.Sub(t); age > r.MaxAge.D() {
				out = append(out, candidate{k.env, k.host, age.Round(time.Minute).String(),
					fmt.Sprintf("no %s since %s", r.Series, t.UTC().Format("2006-01-02 15:04 UTC"))})
			}
		}
	case config.RuleLogRate:
		idx := e.ruleIndex(r.Name)
		for k, ts := range e.hits {
			if k.rule != idx || len(ts) < r.Count || !e.matches(config.Match{Env: r.Match.Env, Host: r.Match.Host, Role: r.Match.Role}, k.env, k.host) {
				continue
			}
			out = append(out, candidate{k.env, k.host, strconv.Itoa(len(ts)), fmt.Sprintf("%d matching log lines in %s", len(ts), r.Per.D())})
		}
	}
	return out
}

func (e *Engine) ruleIndex(name string) int {
	for i, r := range e.rules {
		if r.Name == name {
			return i
		}
	}
	return -1
}

// anomaly: the newest value is more than zscore standard deviations (and min_delta) away from the
// mean of the older values in the window.
func anomaly(r compiled, pts []point) (candidate, bool) {
	if len(pts) < r.MinSamples+1 {
		return candidate{}, false
	}
	hist, last := pts[:len(pts)-1], pts[len(pts)-1].v
	var sum, sq float64
	for _, p := range hist {
		sum += p.v
	}
	mean := sum / float64(len(hist))
	for _, p := range hist {
		sq += (p.v - mean) * (p.v - mean)
	}
	std := math.Sqrt(sq / float64(len(hist)))
	d := math.Abs(last - mean)
	if d < r.MinDelta || d <= r.ZScore*std {
		return candidate{}, false
	}
	return candidate{value: num(last), detail: fmt.Sprintf("%s = %s, usual %s ± %s", r.Series, num(last), num(mean), num(std))}, true
}

func compare(v float64, op string, x float64) bool {
	switch op {
	case ">":
		return v > x
	case ">=":
		return v >= x
	case "<":
		return v < x
	case "<=":
		return v <= x
	case "==":
		return v == x
	case "!=":
		return v != x
	}
	return false
}

func num(v float64) string { return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64) }

func render(r compiled, c candidate) string {
	t := r.Text
	if t == "" {
		t = "{rule}: {detail} on {host} ({env}), value {value}"
	}
	return strings.NewReplacer("{rule}", r.Name, "{env}", c.env, "{host}", c.host, "{value}", c.value, "{detail}", c.detail, "{series}", r.Series).Replace(t)
}
