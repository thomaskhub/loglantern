package report

import (
	"bytes"
	"context"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/record"
	"github.com/thomaskhub/loglantern/internal/store"
)

func TestChart(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ll.db"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)
	var recs []record.Record
	for m := range 24 * 60 {
		ts := now.Add(-time.Duration(24*60-m) * time.Minute)
		recs = append(recs,
			record.Record{Kind: record.KindMetric, TS: ts, Env: "prod", Host: "ishanga-api-eu", Values: map[string]float64{
				"cpu.cpu_p": 30 + 25*math.Sin(float64(m)/90), "mem.Mem.used": 400, "mem.Mem.total": 1000, "mem.swap_pct": 5, "disk.used_pct": 26}},
			record.Record{Kind: record.KindMetric, TS: ts, Env: "prod", Host: "ishanga-db-eu", Values: map[string]float64{
				"cpu.cpu_p": 10, "mem.used_pct": 70, "mem.swap_pct": 0, "disk.used_pct": 40}})
	}
	if err := st.Write(ctx, recs); err != nil {
		t.Fatal(err)
	}
	hosts := []store.Host{{Env: "prod", Host: "ishanga-api-eu"}, {Env: "prod", Host: "ishanga-db-eu"}, {Env: "prod", Host: "ishanga-gateway"}}
	b, err := Chart(ctx, st, "prod", hosts, time.UTC, now)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != chartW || img.Bounds().Dy() != chartH {
		t.Errorf("size %v", img.Bounds())
	}
	blue, red := 0, 0 // first host line colour is blue; a host without data draws nothing
	for y := 0; y < chartH; y++ {
		for x := 0; x < chartW; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			if r>>8 == 0x25 && g>>8 == 0x63 && bl>>8 == 0xeb {
				blue++
			}
			if r>>8 == 0xdc && g>>8 == 0x26 && bl>>8 == 0x26 {
				red++
			}
		}
	}
	if blue < 500 || red < 500 {
		t.Errorf("lines missing: blue %d red %d", blue, red)
	}
	if out := os.Getenv("CHART_OUT"); out != "" {
		_ = os.WriteFile(out, b, 0o644)
	}
}
