package report

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thomaskhub/loglantern/internal/notify"
	"github.com/thomaskhub/loglantern/internal/store"
)

const statusKey = "status_slot"

// StatusDue reports whether the current status slot (now cut to a multiple of every) was not sent yet.
func StatusDue(ctx context.Context, st *store.Store, every time.Duration, now time.Time) (bool, error) {
	last, err := st.Meta(ctx, statusKey)
	if err != nil {
		return false, err
	}
	return last != slot(every, now), nil
}

func slot(every time.Duration, now time.Time) string {
	return strconv.FormatInt(now.Truncate(every).Unix(), 10)
}

// SendStatus queues the host table on route and remembers the slot.
func SendStatus(ctx context.Context, st *store.Store, out *notify.Outbox, hosts []store.Host, route string, every time.Duration, loc *time.Location, now time.Time) (string, error) {
	open := map[string]int{}
	for _, h := range hosts {
		if _, done := open[h.Env]; done {
			continue
		}
		ins, err := st.Incidents(ctx, store.IncidentFilter{Envs: []string{h.Env}, Status: store.StatusOpen, Limit: 1000})
		if err != nil {
			return "", err
		}
		open[h.Env] = len(ins)
	}
	text := BuildStatus(hosts, open, now, loc)
	if err := out.Put(ctx, route, text, 0, false, now); err != nil {
		return "", err
	}
	return text, st.SetMeta(ctx, statusKey, slot(every, now))
}

// BuildStatus renders one monospace table per environment: state and the latest CPU, memory, swap and disk percentages.
func BuildStatus(hosts []store.Host, open map[string]int, now time.Time, loc *time.Location) string {
	byEnv := map[string][]store.Host{}
	for _, h := range hosts {
		byEnv[h.Env] = append(byEnv[h.Env], h)
	}
	envs := make([]string, 0, len(byEnv))
	for e := range byEnv {
		envs = append(envs, e)
	}
	sort.Strings(envs)
	var b strings.Builder
	for i, env := range envs {
		if i > 0 {
			b.WriteString("\n")
		}
		hs := byEnv[env]
		sort.Slice(hs, func(i, j int) bool { return hs[i].Host < hs[j].Host })
		names := make([]string, len(hs))
		for i, h := range hs {
			names[i] = h.Host
		}
		short := shortNames(env, names)
		width := len("host")
		for _, n := range short {
			width = max(width, len(n))
		}
		fmt.Fprintf(&b, "Status %s %s\n```\n", strings.ToUpper(env), now.In(loc).Format("2006-01-02 15:04 MST"))
		fmt.Fprintf(&b, "%-*s  %-4s %3s %3s %3s %3s\n", width, "host", "st", "cpu", "mem", "swp", "dsk")
		var missing []string
		for i, h := range hs {
			state := "up"
			switch h.Status {
			case "missing":
				state = "MISS"
				if h.LastSeen != nil {
					missing = append(missing, fmt.Sprintf("%s (%s)", short[i], now.Sub(*h.LastSeen).Round(time.Minute)))
				} else {
					missing = append(missing, short[i])
				}
			case "up":
			default:
				state = "?"
			}
			fmt.Fprintf(&b, "%-*s  %-4s %3s %3s %3s %3s\n", width, short[i], state,
				val(h.Last, "cpu.cpu_p"),
				pct(h.Last, "mem.used_pct", "mem.Mem.used", "mem.Mem.total"),
				pct(h.Last, "mem.swap_pct", "mem.Swap.used", "mem.Swap.total"),
				val(h.Last, "disk.used_pct"))
		}
		b.WriteString("```\n")
		fmt.Fprintf(&b, "Open incidents: %d\n", open[env])
		if len(missing) > 0 {
			fmt.Fprintf(&b, "Not reporting: %s\n", strings.Join(missing, ", "))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func val(m map[string]float64, key string) string {
	if v, ok := m[key]; ok {
		return strconv.Itoa(int(v + 0.5))
	}
	return "-"
}

// pct prefers a ready percentage (the host checks) and falls back to used/total of Fluent Bit's mem input.
func pct(m map[string]float64, key, used, total string) string {
	if v, ok := m[key]; ok {
		return strconv.Itoa(int(v + 0.5))
	}
	u, ok1 := m[used]
	t, ok2 := m[total]
	if ok1 && ok2 && t > 0 {
		return strconv.Itoa(int(u/t*100 + 0.5))
	}
	return "-"
}

// shortNames drops the "-<env>" suffix and the prefix shared by all hosts (up to a dash) to keep the table narrow.
func shortNames(env string, names []string) []string {
	out := append([]string(nil), names...)
	suffix := "-" + env
	all := len(out) > 0
	for _, n := range out {
		if !strings.HasSuffix(n, suffix) || len(n) == len(suffix) {
			all = false
		}
	}
	if all {
		for i, n := range out {
			out[i] = strings.TrimSuffix(n, suffix)
		}
	}
	if len(out) > 1 {
		p := out[0]
		for _, n := range out[1:] {
			for !strings.HasPrefix(n, p) {
				p = p[:len(p)-1]
			}
		}
		if i := strings.LastIndex(p, "-"); i >= 0 {
			for j, n := range out {
				out[j] = n[i+1:]
			}
		}
	}
	return out
}
