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

// Stat is the average and peak of a metric over the status window.
type Stat struct {
	Avg, Max float64
	OK       bool
}

// Row is one table line: the host and its window statistics. Disk is the latest value.
type Row struct {
	Host           store.Host
	CPU, Mem, Swap Stat
}

// SendStatus queues the host table on route and remembers the slot. CPU, memory and swap are
// averaged over the last "every" minutes from the stored 1-minute values.
func SendStatus(ctx context.Context, st *store.Store, out *notify.Outbox, hosts []store.Host, route string, every time.Duration, loc *time.Location, now time.Time) (string, error) {
	open := map[string]int{}
	rows := make([]Row, 0, len(hosts))
	from := now.Add(-every)
	for _, h := range hosts {
		if _, done := open[h.Env]; !done {
			ins, err := st.Incidents(ctx, store.IncidentFilter{Envs: []string{h.Env}, Status: store.StatusOpen, Limit: 1000})
			if err != nil {
				return "", err
			}
			open[h.Env] = len(ins)
		}
		r := Row{Host: h}
		var err error
		if r.CPU, err = window(ctx, st, h, from, now, "cpu.cpu_p"); err != nil {
			return "", err
		}
		if r.Mem, err = windowPct(ctx, st, h, from, now, "mem.used_pct", "mem.Mem.used", "mem.Mem.total"); err != nil {
			return "", err
		}
		if r.Swap, err = windowPct(ctx, st, h, from, now, "mem.swap_pct", "mem.Swap.used", "mem.Swap.total"); err != nil {
			return "", err
		}
		rows = append(rows, r)
	}
	text := BuildStatus(rows, open, every, now, loc)
	if err := out.Put(ctx, route, text, 0, false, now); err != nil {
		return "", err
	}
	return text, st.SetMeta(ctx, statusKey, slot(every, now))
}

func window(ctx context.Context, st *store.Store, h store.Host, from, to time.Time, name string) (Stat, error) {
	pts, err := st.Series(ctx, h.Env, h.Host, name, from, to)
	if err != nil || len(pts) == 0 {
		return Stat{}, err
	}
	s := Stat{OK: true, Max: pts[0].V}
	var sum float64
	for _, p := range pts {
		sum += p.V
		s.Max = max(s.Max, p.V)
	}
	s.Avg = sum / float64(len(pts))
	return s, nil
}

// windowPct prefers a ready percentage series and falls back to used/total of the averaged
// raw series (the peak is then not known and equals the average).
func windowPct(ctx context.Context, st *store.Store, h store.Host, from, to time.Time, key, used, total string) (Stat, error) {
	if s, err := window(ctx, st, h, from, to, key); err != nil || s.OK {
		return s, err
	}
	u, err := window(ctx, st, h, from, to, used)
	if err != nil || !u.OK {
		return Stat{}, err
	}
	t, err := window(ctx, st, h, from, to, total)
	if err != nil || !t.OK || t.Avg <= 0 {
		return Stat{}, err
	}
	v := u.Avg / t.Avg * 100
	return Stat{Avg: v, Max: u.Max / t.Avg * 100, OK: true}, nil
}

// BuildStatus renders one monospace table per environment: state, CPU, memory and swap as
// average/peak over the window, and the latest disk percentage.
func BuildStatus(rows []Row, open map[string]int, every time.Duration, now time.Time, loc *time.Location) string {
	byEnv := map[string][]Row{}
	for _, r := range rows {
		byEnv[r.Host.Env] = append(byEnv[r.Host.Env], r)
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
		rs := byEnv[env]
		sort.Slice(rs, func(i, j int) bool { return rs[i].Host.Host < rs[j].Host.Host })
		names := make([]string, len(rs))
		for i, r := range rs {
			names[i] = r.Host.Host
		}
		short := shortNames(env, names)
		width := len("host")
		for _, n := range short {
			width = max(width, len(n))
		}
		fmt.Fprintf(&b, "Status %s %s, avg/peak of the last %s\n```\n", strings.ToUpper(env), now.In(loc).Format("2006-01-02 15:04 MST"), every.Round(time.Minute))
		fmt.Fprintf(&b, "%-*s  %-4s %-7s %-7s %-5s %3s\n", width, "host", "st", "cpu", "mem", "swp", "dsk")
		var missing []string
		for i, r := range rs {
			h := r.Host
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
			fmt.Fprintf(&b, "%-*s  %-4s %-7s %-7s %-5s %3s\n", width, short[i], state, r.CPU.cell(), r.Mem.cell(), r.Swap.cell(), val(h.Last, "disk.used_pct"))
		}
		b.WriteString("```\n")
		fmt.Fprintf(&b, "Open incidents: %d\n", open[env])
		if len(missing) > 0 {
			fmt.Fprintf(&b, "Not reporting: %s\n", strings.Join(missing, ", "))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// cell is "avg/peak" in whole percent, "-" without data.
func (s Stat) cell() string {
	if !s.OK {
		return "-"
	}
	return fmt.Sprintf("%d/%d", int(s.Avg+0.5), int(s.Max+0.5))
}

func val(m map[string]float64, key string) string {
	if v, ok := m[key]; ok {
		return strconv.Itoa(int(v + 0.5))
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
