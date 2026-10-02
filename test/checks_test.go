package test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/loglantern/internal/record"
)

// The example checks print facts that loglantern turns into the documented series.
func TestCheckScripts(t *testing.T) {
	cmd := exec.Command("sh", "../examples/checks/system.sh", os.TempDir())
	cmd.Env = append(os.Environ(), "LOGLANTERN_STDOUT=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("system.sh: %v", err)
	}
	values := map[string]float64{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		raw := map[string]any{"host": "h1", "SYSLOG_IDENTIFIER": record.FactIdentifier, "MESSAGE": line}
		r, err := record.Normalize(raw, "uat", time.Now(), record.Options{})
		if err != nil || r.Kind != record.KindFact {
			t.Fatalf("not a fact: %q: %v", line, err)
		}
		for k, v := range r.Values {
			values[k] = v
		}
	}
	for _, s := range []string{"mem.used_pct", "mem.swap_pct", "disk.used_pct", "disk.inodes_pct", "load.per_cpu", "disk_tmp.used_pct"} {
		v, ok := values[s]
		if !ok || v < 0 || (strings.HasSuffix(s, "_pct") && v > 100) {
			t.Errorf("series %s missing or out of range: %v (%v)", s, v, ok)
		}
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if _, ok := values["systemd.failed"]; !ok {
			t.Error("systemd.failed missing")
		}
	}
	if err := exec.Command("sh", "-n", "../examples/checks/postgres.sh").Run(); err != nil {
		t.Errorf("postgres.sh syntax: %v", err)
	}
}
