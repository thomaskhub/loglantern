// Package api serves the JSON REST API for dashboards (REST, SSE, CORS, OpenAPI).
package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thomkin/loglantern/internal/auth"
	"github.com/thomkin/loglantern/internal/store"
)

//go:embed openapi.json
var openapi []byte

// Health reports internal state for /api/v1/health.
type Health func(ctx context.Context) map[string]any

// Server is the API.
type Server struct {
	st     *store.Store
	auth   *auth.Auth
	hub    *Hub
	cors   []string
	health Health
	log    *slog.Logger
	Now    func() time.Time
}

// New creates the API server.
func New(st *store.Store, a *auth.Auth, hub *Hub, cors []string, health Health, log *slog.Logger) *Server {
	return &Server{st: st, auth: a, hub: hub, cors: cors, health: health, log: log, Now: time.Now}
}

type ctxKey struct{}

func principal(r *http.Request) auth.Principal { return r.Context().Value(ctxKey{}).(auth.Principal) }

// Handler returns the routes wrapped in CORS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(openapi)
	})
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"status": "ok"}
		if s.health != nil {
			for k, v := range s.health(r.Context()) {
				out[k] = v
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.Handle("GET /api/v1/me", s.authed(false, false, s.me))
	mux.Handle("GET /api/v1/hosts", s.authed(false, false, s.hosts))
	mux.Handle("GET /api/v1/incidents", s.authed(false, false, s.incidents))
	mux.Handle("GET /api/v1/series", s.authed(false, false, s.series))
	mux.Handle("GET /api/v1/series/names", s.authed(false, false, s.seriesNames))
	mux.Handle("GET /api/v1/counters", s.authed(false, false, s.counters))
	mux.Handle("GET /api/v1/logs", s.authed(true, false, s.logs))
	mux.Handle("GET /api/v1/events", s.authed(false, true, s.events))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { fail(w, http.StatusNotFound, "not found") })
	return s.withCORS(mux)
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && (slices.Contains(s.cors, o) || slices.Contains(s.cors, "*")) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", o)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Last-Event-ID")
			h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			h.Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authed(logs, query bool, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.auth.Check(auth.Token(r, query))
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}
		if logs && !p.CanSeeLogs() {
			fail(w, http.StatusForbidden, "role "+p.Role+" may not read logs")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// envs returns the permitted envs of ?env=a,b (all permitted when absent); 403 when none is left.
func envs(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var req []string
	for _, v := range r.URL.Query()["env"] {
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				req = append(req, e)
			}
		}
	}
	got := principal(r).Allowed(req)
	if len(got) == 0 {
		fail(w, http.StatusForbidden, "no permitted environment")
		return nil, false
	}
	return got, true
}

// parseTime accepts RFC 3339, unix seconds, or a duration back from now ("90m").
func parseTime(v string, now time.Time, def time.Time) (time.Time, error) {
	if v == "" {
		return def, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	if d, err := time.ParseDuration(strings.TrimPrefix(v, "-")); err == nil {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("bad time %q", v)
}

func timeRange(w http.ResponseWriter, r *http.Request, now time.Time, back time.Duration) (time.Time, time.Time, bool) {
	q := r.URL.Query()
	from, err1 := parseTime(q.Get("from"), now, now.Add(-back))
	to, err2 := parseTime(q.Get("to"), now, now)
	if err := errors.Join(err1, err2); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return from, to, false
	}
	return from, to, true
}

func intParam(w http.ResponseWriter, r *http.Request, name string, def, max int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		fail(w, http.StatusBadRequest, "bad "+name)
		return 0, false
	}
	return min(n, max), true
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, principal(r))
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	es, ok := envs(w, r)
	if !ok {
		return
	}
	hs, err := s.st.Hosts(r.Context(), es)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": nonNil(hs)})
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	es, ok := envs(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	status := q.Get("status")
	if status != "" && status != store.StatusOpen && status != store.StatusResolved {
		fail(w, http.StatusBadRequest, "status must be open or resolved")
		return
	}
	now := s.Now()
	since, err := parseTime(q.Get("since"), now, now.Add(-7*24*time.Hour))
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, ok := intParam(w, r, "limit", 100, 500)
	if !ok {
		return
	}
	in, err := s.st.Incidents(r.Context(), store.IncidentFilter{Envs: es, Status: status, Since: since, Limit: limit})
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": nonNil(in)})
}

func (s *Server) series(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	env, host, name := q.Get("env"), q.Get("host"), q.Get("name")
	if env == "" || host == "" || name == "" {
		fail(w, http.StatusBadRequest, "env, host and name are required")
		return
	}
	if !slices.Contains(principal(r).Envs, env) {
		fail(w, http.StatusForbidden, "environment not permitted")
		return
	}
	from, to, ok := timeRange(w, r, s.Now(), 2*time.Hour)
	if !ok {
		return
	}
	ps, err := s.st.Series(r.Context(), env, host, name, from, to)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"env": env, "host": host, "name": name, "points": nonNil(ps)})
}

func (s *Server) seriesNames(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	env, host := q.Get("env"), q.Get("host")
	if env == "" || host == "" {
		fail(w, http.StatusBadRequest, "env and host are required")
		return
	}
	if !slices.Contains(principal(r).Envs, env) {
		fail(w, http.StatusForbidden, "environment not permitted")
		return
	}
	names, err := s.st.SeriesNames(r.Context(), env, host, s.Now().Add(-24*time.Hour))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": nonNil(names)})
}

func (s *Server) counters(w http.ResponseWriter, r *http.Request) {
	es, ok := envs(w, r)
	if !ok {
		return
	}
	from, to, ok := timeRange(w, r, s.Now(), 24*time.Hour)
	if !ok {
		return
	}
	by := r.URL.Query().Get("by")
	if by != "" && by != "host" && by != "service" {
		fail(w, http.StatusBadRequest, "by must be host or service")
		return
	}
	cs, err := s.st.Counters(r.Context(), store.CounterFilter{Envs: es, From: from, To: to, ByHost: by == "host", ByServ: by == "service"})
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"counters": nonNil(cs)})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	es, ok := envs(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	from, to, ok := timeRange(w, r, s.Now(), time.Hour)
	if !ok {
		return
	}
	level, ok := intParam(w, r, "level", 7, 7)
	if !ok {
		return
	}
	limit, ok := intParam(w, r, "limit", 200, 1000)
	if !ok {
		return
	}
	var before int64
	if c := q.Get("cursor"); c != "" {
		if before, _ = strconv.ParseInt(c, 10, 64); before <= 0 {
			fail(w, http.StatusBadRequest, "bad cursor")
			return
		}
	}
	lines, next, err := s.st.Logs(r.Context(), store.LogFilter{Envs: es, Host: q.Get("host"), Service: q.Get("service"), MaxLevel: level,
		Text: q.Get("q"), From: from, To: to, Before: before, Limit: limit})
	if err != nil {
		s.internal(w, err)
		return
	}
	out := map[string]any{"logs": nonNil(lines), "next": nil}
	if next > 0 {
		out["next"] = strconv.FormatInt(next, 10)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	es, ok := envs(w, r)
	if !ok {
		return
	}
	ch, cancel := s.hub.Subscribe(es)
	defer cancel()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 5000\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
		case ev, ok := <-ch:
			if !ok {
				return // hub closed or subscriber too slow
			}
			b, _ := json.Marshal(ev.Data)
			_, _ = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, b)
		}
		fl.Flush()
	}
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("api", "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

// nonNil makes empty lists encode as [] for clients.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
