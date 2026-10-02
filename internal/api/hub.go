package api

import (
	"slices"
	"sync"
)

// Event is pushed to SSE subscribers.
type Event struct {
	ID   int64  `json:"id"`
	Type string `json:"type"` // incident | host
	Env  string `json:"env"`
	Data any    `json:"data"`
}

// Hub fans events out to subscribers filtered by environment.
type Hub struct {
	mu   sync.Mutex
	next int64
	subs map[*sub]struct{}
}

type sub struct {
	envs []string
	ch   chan Event
}

// NewHub creates an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*sub]struct{}{}} }

// Subscribe returns a channel of events for these envs; cancel must be called.
func (h *Hub) Subscribe(envs []string) (<-chan Event, func()) {
	s := &sub{envs: envs, ch: make(chan Event, 64)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[s]; ok {
			delete(h.subs, s)
			close(s.ch)
		}
	}
}

// Publish sends an event; a subscriber whose buffer is full is dropped (the client reconnects).
func (h *Hub) Publish(typ, env string, data any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	ev := Event{ID: h.next, Type: typ, Env: env, Data: data}
	for s := range h.subs {
		if !slices.Contains(s.envs, env) {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			delete(h.subs, s)
			close(s.ch)
		}
	}
}

// Count returns the number of subscribers.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
