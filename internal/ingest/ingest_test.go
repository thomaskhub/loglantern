package ingest

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
)

func setup(t *testing.T, sink Sink) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		Envs:    map[string]config.Env{"uat": {IngestTokenEnv: "T_UAT"}, "prod": {IngestTokenEnv: "T_PROD"}},
		Ingest:  config.Ingest{MaxBodyMB: 1, MaskEmails: true},
		Secrets: map[string]string{"T_UAT": "tok-uat", "T_PROD": "tok-prod"},
	}
	h, err := New(cfg, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h.Now = func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }
	mux := http.NewServeMux()
	h.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func send(t *testing.T, url, auth, enc string, body []byte) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestIngest(t *testing.T) {
	var got []record.Record
	busy := false
	srv := setup(t, func(r []record.Record) error {
		if busy {
			return ErrBusy
		}
		got = append(got, r...)
		return nil
	})
	arr := []byte(`[{"date":1790000000.5,"host":"h1","SYSLOG_IDENTIFIER":"api","PRIORITY":"3","MESSAGE":"fail for a@b.com"},{"date":1790000001,"host":"h1","kind":"metric","source":"cpu","cpu_p":42.5}]`)

	if c := send(t, srv.URL+"/", "", "", arr); c != 401 {
		t.Fatalf("G1 no token: %d", c)
	}
	if c := send(t, srv.URL+"/", "nope", "", arr); c != 401 {
		t.Fatalf("G1 wrong token: %d", c)
	}
	if c := send(t, srv.URL+"/", "tok-prod", "", arr); c != 204 {
		t.Fatalf("G2 array: %d", c)
	}
	if len(got) != 2 || got[0].Env != "prod" || strings.Contains(got[0].Message, "a@b.com") || got[1].Values["cpu.cpu_p"] != 42.5 {
		t.Fatalf("G2 records: %+v", got)
	}
	got = nil
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("{\"host\":\"h2\",\"MESSAGE\":\"one\"}\n\n{\"host\":\"h2\",\"MESSAGE\":\"two\"}\n"))
	_ = zw.Close()
	if c := send(t, srv.URL+"/ingest", "tok-uat", "gzip", gz.Bytes()); c != 204 || len(got) != 2 || got[1].Env != "uat" {
		t.Fatalf("G3 gzip json lines: %d %+v", c, got)
	}
	if c := send(t, srv.URL+"/", "tok-uat", "", []byte(`[{"host":`)); c != 400 {
		t.Fatalf("G4 bad json: %d", c)
	}
	if c := send(t, srv.URL+"/", "tok-uat", "gzip", []byte("not gzip")); c != 400 {
		t.Fatalf("G4 bad gzip: %d", c)
	}
	big := bytes.Repeat([]byte(" "), 2<<20)
	if c := send(t, srv.URL+"/", "tok-uat", "", big); c != 413 && c != 400 {
		t.Fatalf("G5 too large: %d", c)
	}
	var bomb bytes.Buffer
	zw = gzip.NewWriter(&bomb)
	_, _ = zw.Write(bytes.Repeat([]byte(" "), 4<<20))
	_ = zw.Close()
	if c := send(t, srv.URL+"/", "tok-uat", "gzip", bomb.Bytes()); c != 413 {
		t.Fatalf("G5 gzip bomb: %d", c)
	}
	busy = true
	if c := send(t, srv.URL+"/", "tok-uat", "", arr); c != 503 {
		t.Fatalf("G6 busy -> 503 so Fluent Bit retries: %d", c)
	}
}

func TestEmptyToken(t *testing.T) {
	cfg := &config.Config{Envs: map[string]config.Env{"uat": {IngestTokenEnv: "MISSING"}}}
	if _, err := New(cfg, nil, nil); err == nil {
		t.Fatal("env without token accepted")
	}
}
