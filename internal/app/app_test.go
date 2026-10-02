package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/ingest"
	"github.com/thomkin/loglantern/internal/record"
)

// A full queue answers busy so Fluent Bit keeps the data and retries.
func TestSinkBusy(t *testing.T) {
	t.Setenv("LL_T", "tok")
	cfg, err := config.Parse([]byte("storage: {path: " + filepath.Join(t.TempDir(), "x.db") + "}\nenvs: {uat: {ingest_token_env: LL_T}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	batch := []record.Record{{Kind: record.KindLog, Env: "uat", Host: "h"}}
	for i := range queueSize {
		if err := a.sink(batch); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}
	if err := a.sink(batch); !errors.Is(err, ingest.ErrBusy) {
		t.Fatalf("full queue: %v", err)
	}
}

func TestReportReview(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"restart db-1"}}]}`)
	}))
	defer srv.Close()
	t.Setenv("LL_T", "tok")
	cfg, err := config.Parse([]byte("storage: {path: " + filepath.Join(t.TempDir(), "x.db") + "}\nenvs: {uat: {ingest_token_env: LL_T}}\n" +
		"routes: [{name: daily, notifier: webhook}, {name: ops, notifier: webhook}]\nnotifiers: {webhook: {url_env: LL_T}}\n" +
		"ai: {base_url: " + srv.URL + ", key_env: LL_T, model: m, agents: [{name: review, on: daily_report}, {name: ops, on: daily_report, route: ops}, {name: explain, on: incident_open}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	a.reviewReport("Daily report", "daily")
	a.bgWork.Wait()
	msgs, _ := a.st.Due(context.Background(), time.Now().Add(time.Hour), 10)
	var got []string
	for _, m := range msgs {
		got = append(got, m.Route+"|"+m.Text)
	}
	if strings.Join(got, ",") != "daily|[AI review] restart db-1,ops|[AI ops] restart db-1" {
		t.Fatalf("report agents: %q", got)
	}
}
