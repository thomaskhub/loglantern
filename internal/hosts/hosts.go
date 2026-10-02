// Package hosts keeps the heartbeat registry: every known (configured) and seen host with its IP,
// role, status and last values. A host that sent nothing for missing_after is "missing".
package hosts

import (
	"sort"
	"sync"
	"time"

	"github.com/thomkin/loglantern/internal/record"
	"github.com/thomkin/loglantern/internal/store"
)

// Statuses.
const (
	Up      = "up"
	Missing = "missing"
	Unknown = "unknown" // known host, nothing received yet (until missing_after after start)
)

type key struct{ env, host string }

// Registry is safe for concurrent use.
type Registry struct {
	mu           sync.Mutex
	hosts        map[key]*store.Host
	missingAfter time.Duration
	started      time.Time
}

// New creates the registry with the known hosts (status unknown) and stored rows.
func New(known []store.Host, saved []store.Host, missingAfter time.Duration, now time.Time) *Registry {
	r := &Registry{hosts: map[key]*store.Host{}, missingAfter: missingAfter, started: now}
	for _, h := range saved {
		h := h
		h.Known = false
		r.hosts[key{h.Env, h.Host}] = &h
	}
	for _, k := range known {
		h, ok := r.hosts[key{k.Env, k.Host}]
		if !ok {
			h = &store.Host{Env: k.Env, Host: k.Host, Status: Unknown}
			r.hosts[key{k.Env, k.Host}] = h
		}
		h.Known = true
		if k.Role != "" {
			h.Role = k.Role
		}
	}
	return r
}

// Seen records a received record.
func (r *Registry) Seen(rec record.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hosts[key{rec.Env, rec.Host}]
	if rec.Synthetic { // probes and Lightsail: keep values of existing hosts, but no heartbeat
		if ok {
			setLast(h, rec.Values)
		}
		return
	}
	if !ok {
		h = &store.Host{Env: rec.Env, Host: rec.Host}
		r.hosts[key{rec.Env, rec.Host}] = h
	}
	if h.LastSeen == nil || rec.TS.After(*h.LastSeen) {
		t := rec.TS
		h.LastSeen = &t
	}
	if rec.IP != "" {
		h.IP = rec.IP
	}
	if rec.Role != "" {
		h.Role = rec.Role
	}
	setLast(h, rec.Values)
	if h.Status != Missing { // the way back from missing is reported by Check
		h.Status = Up
	}
}

func setLast(h *store.Host, vals map[string]float64) {
	if len(vals) == 0 {
		return
	}
	if h.Last == nil {
		h.Last = map[string]float64{}
	}
	for k, v := range vals {
		h.Last[k] = v
	}
}

// Change is a status transition to or from missing.
type Change struct {
	Env, Host string
	Missing   bool
	LastSeen  *time.Time
}

// Check updates the statuses at now and returns the transitions to/from missing.
func (r *Registry) Check(now time.Time) []Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Change
	for _, h := range r.hosts {
		silent := h.LastSeen == nil || now.Sub(*h.LastSeen) > r.missingAfter
		switch {
		case silent && h.Status != Missing && now.Sub(r.started) <= r.missingAfter:
			// grace after a restart: nothing could arrive while loglantern was down
			if h.LastSeen == nil {
				h.Status = Unknown
			}
		case silent && h.Status != Missing && (h.Known || h.LastSeen != nil):
			h.Status = Missing
			out = append(out, Change{Env: h.Env, Host: h.Host, Missing: true, LastSeen: h.LastSeen})
		case !silent && h.Status == Missing:
			h.Status = Up
			out = append(out, Change{Env: h.Env, Host: h.Host, Missing: false, LastSeen: h.LastSeen})
		case !silent:
			h.Status = Up
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env+out[i].Host < out[j].Env+out[j].Host })
	return out
}

// Role returns the role of a host ("" if unknown).
func (r *Registry) Role(env, host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.hosts[key{env, host}]; ok {
		return h.Role
	}
	return ""
}

// Snapshot returns copies of all rows (for persistence and the API).
func (r *Registry) Snapshot() []store.Host {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]store.Host, 0, len(r.hosts))
	for _, h := range r.hosts {
		c := *h
		if h.Last != nil {
			c.Last = make(map[string]float64, len(h.Last))
			for k, v := range h.Last {
				c.Last[k] = v
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env+out[i].Host < out[j].Env+out[j].Host })
	return out
}
