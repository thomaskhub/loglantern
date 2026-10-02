package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

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
