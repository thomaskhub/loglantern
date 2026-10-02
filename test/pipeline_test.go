// Package test runs the whole binary pipeline in-process: ingest → rules → incidents → outbox → notifier, plus the API.
package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/app"
	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/notify"
)

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (f *fakeNotifier) Send(_ context.Context, target, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, target+"|"+text)
	return nil
}

func (f *fakeNotifier) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func (f *fakeNotifier) waitFor(t *testing.T, sub string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range f.all() {
			if strings.Contains(m, sub) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no message containing %q; got %q", sub, f.all())
}

const cfgYAML = `
storage: {path: %q}
envs: {uat: {ingest_token_env: LL_TEST_TOKEN}}
hosts: [{env: uat, host: db1, role: db}]
missing_after: 1500ms
tick: 200ms
rules:
  - {name: cpu, type: threshold, series: cpu.cpu_p, op: ">", value: "90", severity: critical}
  - {name: errors, type: lograte, level: err, count: 2, per: 1m}
routes:
  - {name: all, notifier: telegram, target: alerts}
notifiers:
  telegram: {token_env: LL_TEST_TG, chat_id: "-1", topics: {alerts: 7}}
auth:
  api_keys: [{name: dash, key_env: LL_TEST_KEY, role: logs}]
`

type running struct {
	ingest, api string
	notifier    *fakeNotifier
	stop        func()
}

func start(t *testing.T, dbPath string) *running { return startOn(t, dbPath, "127.0.0.1:0") }

func startOn(t *testing.T, dbPath, ingestAddr string) *running {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(cfgYAML, dbPath)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	n := &fakeNotifier{}
	a.Notifiers = map[string]notify.Notifier{"telegram": n}
	il, err := net.Listen("tcp", ingestAddr)
	if err != nil {
		t.Fatal(err)
	}
	al, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() { _ = a.Run(ctx, il, al); close(done) }()
	r := &running{ingest: "http://" + il.Addr().String(), api: "http://" + al.Addr().String(), notifier: n}
	r.stop = func() { cancel(); <-done }
	return r
}

func (r *running) send(t *testing.T, recs ...map[string]any) {
	t.Helper()
	b, _ := json.Marshal(recs)
	req, _ := http.NewRequest(http.MethodPost, r.ingest+"/", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer tok-0123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("ingest: %d", resp.StatusCode)
	}
}

func (r *running) get(t *testing.T, path string, out any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, r.api+path, nil)
	req.Header.Set("Authorization", "Bearer dash-key-0123456789")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", path, resp.StatusCode)
	}
	_ = json.NewDecoder(resp.Body).Decode(out)
}

func metric(v float64) map[string]any {
	return map[string]any{"date": float64(time.Now().UnixMilli()) / 1000, "host": "h1", "kind": "metric", "source": "cpu", "cpu_p": v}
}

func TestPipeline(t *testing.T) {
	t.Setenv("LL_TEST_TOKEN", "tok-0123")
	t.Setenv("LL_TEST_TG", "x")
	t.Setenv("LL_TEST_KEY", "dash-key-0123456789")
	db := filepath.Join(t.TempDir(), "ll.db")
	r := start(t, db)

	// A1: metric over threshold → one message; back under → resolved
	r.send(t, metric(95))
	r.notifier.waitFor(t, "alerts|[CRITICAL] uat/h1")
	r.send(t, metric(10))
	r.notifier.waitFor(t, "[RESOLVED] uat/h1")

	// A1: lograte from journald-style lines
	line := func(msg string) map[string]any {
		return map[string]any{"host": "h1", "SYSLOG_IDENTIFIER": "api", "PRIORITY": "3", "MESSAGE": msg}
	}
	r.send(t, line("boom 1"), line("boom 2"))
	r.notifier.waitFor(t, "[WARNING] uat/h1")

	// A4: known host that never reports → missing
	r.notifier.waitFor(t, "db1 (uat) sends no data")

	// API sees the same state
	var inc struct {
		Incidents []struct{ Rule, Status string }
	}
	r.get(t, "/api/v1/incidents", &inc)
	got := map[string]string{}
	for _, i := range inc.Incidents {
		got[i.Rule] = i.Status
	}
	if got["cpu"] != "resolved" || got["errors"] != "open" || got["host-missing"] != "open" {
		t.Fatalf("API incidents: %v", got)
	}
	var logs struct{ Logs []struct{ Msg string } }
	r.get(t, "/api/v1/logs?q=boom", &logs)
	if len(logs.Logs) != 2 {
		t.Fatalf("API logs: %+v", logs)
	}
	var hosts struct {
		Hosts []struct{ Host, Status string }
	}
	r.get(t, "/api/v1/hosts", &hosts)
	if len(hosts.Hosts) != 2 {
		t.Fatalf("API hosts: %+v", hosts)
	}
	before := len(r.notifier.all())
	r.stop()

	// A2/A5 restart: open incidents are not sent again; db1 still missing, errors still open
	r2 := start(t, db)
	defer r2.stop()
	time.Sleep(time.Second)
	for _, m := range r2.notifier.all() {
		if !strings.Contains(m, "RESOLVED") {
			t.Fatalf("restart re-sent an open incident: %q", m)
		}
	}
	// db1 reports now → back
	r2.send(t, map[string]any{"host": "db1", "MESSAGE": "hello", "PRIORITY": "6"})
	r2.notifier.waitFor(t, "db1 (uat) sends data again")
	if before == 0 {
		t.Fatal("no messages before restart")
	}
}
