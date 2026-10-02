// Package ingest receives Fluent Bit http output (JSON array or JSON lines, optionally gzip).
package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/record"
)

// ErrBusy is returned by a sink that cannot take more records now.
var ErrBusy = errors.New("busy")

// Sink takes normalised records of one request.
type Sink func(recs []record.Record) error

// Stats are counters since start.
type Stats struct {
	Requests, Records, Invalid, Rejected, Busy atomic.Int64
}

// Handler serves POST / and POST /ingest.
type Handler struct {
	tokens  []token
	sink    Sink
	opts    record.Options
	maxBody int64
	log     *slog.Logger
	Now     func() time.Time
	Stats   Stats
}

type token struct {
	value []byte
	env   string
}

// New builds a handler; every env needs a non-empty token.
func New(cfg *config.Config, sink Sink, log *slog.Logger) (*Handler, error) {
	h := &Handler{sink: sink, opts: record.Options{MaskEmails: cfg.Ingest.MaskEmails}, maxBody: int64(cfg.Ingest.MaxBodyMB) << 20, log: log, Now: time.Now}
	for env, e := range cfg.Envs {
		v := cfg.Secret(e.IngestTokenEnv)
		if v == "" {
			return nil, errors.New("ingest: empty token for env " + env)
		}
		h.tokens = append(h.tokens, token{[]byte(v), env})
	}
	return h, nil
}

// Routes registers the handler on a mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /{$}", h.ingest)
	mux.HandleFunc("POST /ingest", h.ingest)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
}

// env returns the environment of the request token (constant time over all tokens).
func (h *Handler) env(r *http.Request) (string, bool) {
	got := r.Header.Get("X-Loglantern-Token")
	if a := r.Header.Get("Authorization"); got == "" && len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		got = a[7:]
	}
	env, ok := "", false
	for _, t := range h.tokens {
		if subtle.ConstantTimeCompare([]byte(got), t.value) == 1 {
			env, ok = t.env, true
		}
	}
	return env, ok && got != ""
}

func (h *Handler) ingest(w http.ResponseWriter, r *http.Request) {
	h.Stats.Requests.Add(1)
	env, ok := h.env(r)
	if !ok {
		h.Stats.Rejected.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body := io.Reader(http.MaxBytesReader(w, r.Body, h.maxBody))
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		body = gz
	}
	data, err := io.ReadAll(io.LimitReader(body, h.maxBody+1))
	if err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(data)) > h.maxBody {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	raws, err := decode(data)
	if err != nil {
		h.Stats.Invalid.Add(1)
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	now := h.Now()
	recs := make([]record.Record, 0, len(raws))
	for _, raw := range raws {
		rec, err := record.Normalize(raw, env, now, h.opts)
		if err != nil {
			h.Stats.Invalid.Add(1)
			continue
		}
		recs = append(recs, rec)
	}
	if len(recs) > 0 {
		if err := h.sink(recs); err != nil {
			// Fluent Bit retries on 5xx: no record is lost while we are full
			h.Stats.Busy.Add(1)
			w.Header().Set("Retry-After", "5")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
	}
	h.Stats.Records.Add(int64(len(recs)))
	w.WriteHeader(http.StatusNoContent)
}

// decode accepts a JSON array, one object, or JSON lines.
func decode(data []byte) ([]map[string]any, error) {
	data = bytes.TrimSpace(data)
	switch {
	case len(data) == 0:
		return nil, nil
	case data[0] == '[':
		var out []map[string]any
		d := json.NewDecoder(bytes.NewReader(data))
		if err := d.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	}
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), len(data)+1)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(line))
		if err := d.Decode(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, sc.Err()
}
