package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/auth"
	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
	"github.com/thomaskhub/loglantern/internal/store"
)

const (
	viewerKey    = "viewer-key-0123456789"
	logsKey      = "logs-key-0123456789ab"
	adminKey     = "admin-key-0123456789a"
	prodAdminKey = "prod-admin-key-012345"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*httptest.Server, *Hub) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	var recs []record.Record
	for i := range 5 {
		for _, env := range []string{"uat", "prod"} {
			ts := now.Add(-time.Duration(10+i) * time.Minute)
			recs = append(recs,
				record.Record{Kind: record.KindLog, TS: ts, Env: env, Host: "h1", Service: "api", Level: 3 + i%2, Message: env + " line " + string(rune('a'+i))},
				record.Record{Kind: record.KindMetric, TS: ts, Env: env, Host: "h1", Values: map[string]float64{"cpu.cpu_p": float64(i)}})
		}
	}
	if err := st.Write(ctx, recs); err != nil {
		t.Fatal(err)
	}
	seen := now.Add(-time.Minute)
	_ = st.SaveHosts(ctx, []store.Host{{Env: "uat", Host: "h1", Status: "up", LastSeen: &seen}, {Env: "prod", Host: "h1", Status: "up", LastSeen: &seen}})
	_, _, _ = st.OpenIncident(ctx, store.Incident{Key: "cpu/prod/h1", Rule: "cpu", Env: "prod", Host: "h1", Severity: "warning", Opened: now.Add(-time.Hour), Text: "cpu"})
	cfg := &config.Config{
		Envs: map[string]config.Env{"uat": {}, "prod": {}},
		Auth: config.Auth{APIKeys: []config.APIKey{
			{Name: "board", KeyEnv: "V", Role: config.RoleViewer, Envs: []string{"prod"}},
			{Name: "dev", KeyEnv: "L", Role: config.RoleLogs},
			{Name: "ops", KeyEnv: "A", Role: config.RoleAdmin},
			{Name: "prod-ops", KeyEnv: "AP", Role: config.RoleAdmin, Envs: []string{"prod"}},
		}},
		Secrets: map[string]string{"V": viewerKey, "L": logsKey, "A": adminKey, "AP": prodAdminKey},
	}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub()
	s := New(st, a, hub, []string{"https://dash.example"}, func(context.Context) map[string]any { return map[string]any{"outbox_pending": 0} },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Now = func() time.Time { return now }
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, hub
}

func get(t *testing.T, url, key string, out any) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestAccess(t *testing.T) {
	srv, _ := setup(t)
	u := srv.URL + "/api/v1/"
	if c := get(t, u+"hosts", "", nil); c != 401 {
		t.Fatalf("P1 no token: %d", c)
	}
	var hosts struct{ Hosts []store.Host }
	if c := get(t, u+"hosts", viewerKey, &hosts); c != 200 || len(hosts.Hosts) != 1 || hosts.Hosts[0].Env != "prod" {
		t.Fatalf("P2 viewer sees prod only: %d %+v", c, hosts)
	}
	if c := get(t, u+"hosts?env=uat", viewerKey, nil); c != 403 {
		t.Fatalf("P2 viewer asks uat: %d", c)
	}
	if c := get(t, u+"series?env=uat&host=h1&name=cpu.cpu_p", viewerKey, nil); c != 403 {
		t.Fatalf("P2 series of other env: %d", c)
	}
	if c := get(t, u+"logs", viewerKey, nil); c != 403 {
		t.Fatalf("P3 viewer reads logs: %d", c)
	}
	var me auth.Principal
	if c := get(t, u+"me", logsKey, &me); c != 200 || me.Role != "logs" || len(me.Envs) != 2 {
		t.Fatalf("P4 me: %+v", me)
	}
	var inc struct{ Incidents []store.Incident }
	if c := get(t, u+"incidents?status=open", viewerKey, &inc); c != 200 || len(inc.Incidents) != 1 {
		t.Fatalf("P5 incidents: %d %+v", c, inc)
	}
	if c := get(t, u+"incidents?status=bogus", viewerKey, nil); c != 400 {
		t.Fatalf("P5 bad status: %d", c)
	}
	var pts struct{ Points []store.Point }
	if c := get(t, u+"series?env=prod&host=h1&name=cpu.cpu_p&from=1h", viewerKey, &pts); c != 200 || len(pts.Points) != 5 {
		t.Fatalf("P6 series: %d %+v", c, pts)
	}
	if c := get(t, u+"series?env=prod&host=h1&name=cpu.cpu_p&from=yesterday", viewerKey, nil); c != 400 {
		t.Fatalf("P6 bad time: %d", c)
	}
	var cnt struct{ Counters []store.Counter }
	if c := get(t, u+"counters?by=service", viewerKey, &cnt); c != 200 || len(cnt.Counters) == 0 {
		t.Fatalf("P7 counters: %d %+v", c, cnt)
	}
	var empty map[string]json.RawMessage
	if get(t, u+"incidents?since=1s", viewerKey, &empty); string(empty["incidents"]) != "[]" {
		t.Fatalf("P8 empty list must be []: %s", empty["incidents"])
	}
	if c := get(t, u+"nope", logsKey, nil); c != 404 {
		t.Fatalf("404: %d", c)
	}
}

func TestLogsPaging(t *testing.T) {
	srv, _ := setup(t)
	type page struct {
		Logs []store.LogLine
		Next *string
	}
	var p page
	if c := get(t, srv.URL+"/api/v1/logs?env=uat&limit=2", logsKey, &p); c != 200 || len(p.Logs) != 2 || p.Next == nil {
		t.Fatalf("L1 first page: %d %+v", c, p)
	}
	seen := len(p.Logs)
	for p.Next != nil {
		next := *p.Next
		p = page{}
		get(t, srv.URL+"/api/v1/logs?env=uat&limit=2&cursor="+next, logsKey, &p)
		seen += len(p.Logs)
	}
	if seen != 5 {
		t.Fatalf("L1 all pages: %d", seen)
	}
	p = page{}
	if get(t, srv.URL+"/api/v1/logs?level=3&q=line", logsKey, &p); len(p.Logs) != 6 {
		t.Fatalf("L2 level filter over both envs: %d", len(p.Logs))
	}
	if c := get(t, srv.URL+"/api/v1/logs?cursor=x", logsKey, nil); c != 400 {
		t.Fatalf("L3 bad cursor: %d", c)
	}
}

func TestCORSOpenAPIHealth(t *testing.T) {
	srv, _ := setup(t)
	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/v1/hosts", nil)
	req.Header.Set("Origin", "https://dash.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "https://dash.example" || !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("C1 preflight: %d %v", resp.StatusCode, resp.Header)
	}
	req.Header.Set("Origin", "https://evil.example")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("C2 foreign origin allowed")
	}
	var doc map[string]any
	if c := get(t, srv.URL+"/api/v1/openapi.json", "", &doc); c != 200 || doc["openapi"] != "3.1.0" {
		t.Fatalf("C3 openapi: %d", c)
	}
	var h map[string]any
	if c := get(t, srv.URL+"/api/v1/health", "", &h); c != 200 || h["status"] != "ok" || h["outbox_pending"] != float64(0) {
		t.Fatalf("C4 health: %v", h)
	}
}

func TestEvents(t *testing.T) {
	srv, hub := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events?access_token="+viewerKey, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("S1: %d", resp.StatusCode)
	}
	for hub.Count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	hub.Publish("incident", "uat", map[string]string{"key": "hidden"}) // viewer is prod-only
	hub.Publish("incident", "prod", map[string]string{"key": "cpu/prod/h1"})
	sc := bufio.NewScanner(resp.Body)
	var lines []string
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "data:") || strings.HasPrefix(l, "event:") {
			lines = append(lines, l)
			if strings.HasPrefix(l, "data:") {
				break
			}
		}
	}
	if strings.Join(lines, "|") != `event: incident|data: {"key":"cpu/prod/h1"}` {
		t.Fatalf("S2 env-filtered event: %q", lines)
	}
	if c := get(t, srv.URL+"/api/v1/hosts?access_token="+viewerKey, "", nil); c != 401 {
		t.Fatalf("S3 query token outside events: %d", c)
	}
}

func TestHubSlowSubscriber(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe([]string{"uat"})
	for range 100 {
		h.Publish("host", "uat", nil)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 64 || h.Count() != 0 {
		t.Fatalf("slow subscriber: got %d, subs %d", n, h.Count())
	}
	cancel() // second close must not panic
}

func call(t *testing.T, method, url, key, body string, out any) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestSilences(t *testing.T) {
	srv, _ := setup(t)
	u := srv.URL + "/api/v1/silences"
	body := `{"env":"prod","host":"h1","duration":"2h","comment":"deploy"}`
	if c := call(t, "POST", u, logsKey, body, nil); c != 403 {
		t.Fatalf("Q1 logs role creates silence: %d", c)
	}
	var x store.Silence
	if c := call(t, "POST", u, prodAdminKey, body, &x); c != 201 || x.ID == 0 || x.CreatedBy != "prod-ops" || !x.Ends.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("Q2 create: %d %+v", c, x)
	}
	for name, b := range map[string]string{
		"other env": `{"env":"uat","duration":"1h","comment":"x"}`,
		"no env":    `{"duration":"1h","comment":"x"}`,
	} {
		if c := call(t, "POST", u, prodAdminKey, b, nil); c != 403 {
			t.Errorf("Q3 %s: %d", name, c)
		}
	}
	for name, b := range map[string]string{
		"no comment":   `{"env":"prod","duration":"1h"}`,
		"past":         `{"env":"prod","ends":"2020-01-01T00:00:00Z","comment":"x"}`,
		"too long":     `{"env":"prod","duration":"800h","comment":"x"}`,
		"both":         `{"env":"prod","duration":"1h","ends":"2030-01-01T00:00:00Z","comment":"x"}`,
		"bad severity": `{"env":"prod","duration":"1h","comment":"x","severity":["loud"]}`,
		"unknown":      `{"env":"prod","duration":"1h","comment":"x","forever":true}`,
	} {
		if c := call(t, "POST", u, adminKey, b, nil); c != 400 {
			t.Errorf("Q4 %s: %d", name, c)
		}
	}
	if c := call(t, "POST", u, adminKey, `{"duration":"1h","comment":"all envs"}`, nil); c != 201 {
		t.Fatalf("Q5 env-less silence by all-env admin: %d", c)
	}
	var list struct{ Silences []store.Silence }
	call(t, "GET", u, viewerKey, "", &list)
	if len(list.Silences) != 1 || list.Silences[0].Env != "prod" {
		t.Fatalf("Q6 prod viewer sees only prod silences: %+v", list)
	}
	call(t, "GET", u, adminKey, "", &list)
	if len(list.Silences) != 2 {
		t.Fatalf("Q6 admin sees all: %+v", list)
	}
	other := list.Silences[0].ID // newest: the env-less one
	if c := call(t, "DELETE", fmt.Sprintf("%s/%d", u, other), prodAdminKey, "", nil); c != 404 {
		t.Fatalf("Q7 prod admin ends env-less silence: %d", c)
	}
	if c := call(t, "DELETE", fmt.Sprintf("%s/%d", u, x.ID), viewerKey, "", nil); c != 403 {
		t.Fatalf("Q7 viewer ends silence: %d", c)
	}
	if c := call(t, "DELETE", fmt.Sprintf("%s/%d", u, x.ID), prodAdminKey, "", nil); c != 204 {
		t.Fatalf("Q8 end: %d", c)
	}
	call(t, "GET", u, adminKey, "", &list)
	if len(list.Silences) != 1 {
		t.Fatalf("Q8 ended silence still listed: %+v", list)
	}
}
