package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fbImage = "docker.io/fluent/fluent-bit:4.0"

// TestFluentBit sends real Fluent Bit http output (gzip, json, double dates) through the example filters.
func TestFluentBit(t *testing.T) {
	if testing.Short() {
		t.Skip("container test")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not installed")
	}
	t.Setenv("LL_TEST_TOKEN", "tok-0123")
	t.Setenv("LL_TEST_TG", "x")
	t.Setenv("LL_TEST_KEY", "dash-key-0123456789")
	db := filepath.Join(t.TempDir(), "ll.db")
	r := start(t, db)
	stopped := false
	defer func() {
		if !stopped {
			r.stop()
		}
	}()

	// the example config with journald replaced by dummy inputs (no journald in a container)
	ex, err := os.ReadFile("../examples/fluent-bit/fluent-bit.conf")
	if err != nil {
		t.Fatal(err)
	}
	conf := string(ex)
	i, j := strings.Index(conf, "[INPUT]\n    name              systemd"), strings.Index(conf, "[INPUT]\n    name          cpu")
	if i < 0 || j < 0 {
		t.Fatal("example layout changed")
	}
	dummy := `[INPUT]
    name   dummy
    tag    log.app
    rate   2
    dummy  {"MESSAGE":"payment failed","PRIORITY":"3","SYSLOG_IDENTIFIER":"api"}

[INPUT]
    name   dummy
    tag    log.fact
    rate   1
    dummy  {"MESSAGE":"{\"fact\":\"backup\",\"status\":\"ok\",\"age_h\":3}","PRIORITY":"6","SYSLOG_IDENTIFIER":"loglantern-fact"}

`
	conf = conf[:i] + dummy + conf[j:]
	conf = strings.ReplaceAll(conf, "interval_sec  60", "interval_sec  1")
	conf = strings.ReplaceAll(conf, "/var/lib/fluent-bit/buffer", "/tmp/fb-buffer")
	port := r.ingest[strings.LastIndex(r.ingest, ":")+1:]
	conf = strings.Replace(conf, "port              8440", "port              "+port, 1)
	conf = strings.Replace(conf, "flush                     5", "flush                     1", 1)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fb.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ll-e2e-%d", time.Now().UnixNano())
	cmd := exec.Command("podman", "run", "--rm", "--name", name, "--network", "host", "-v", dir+":/cfg:Z",
		"-e", "LOGLANTERN_TOKEN=tok-0123", "-e", "LOGLANTERN_HOST=fb-e2e", "-e", "HOST_ROLE=api", "-e", "LOGLANTERN_ADDR=127.0.0.1",
		fbImage, "-c", "/cfg/fb.conf")
	out := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = exec.Command("podman", "rm", "-f", name).Run()
		_ = cmd.Wait()
	}()

	deadline := time.Now().Add(60 * time.Second)
	var names struct{ Names []string }
	for time.Now().Before(deadline) {
		names.Names = nil
		r.get(t, "/api/v1/series/names?env=uat&host=fb-e2e", &names)
		have := strings.Join(names.Names, ",")
		if strings.Contains(have, "cpu.cpu_p") && strings.Contains(have, "mem.Mem.used") && strings.Contains(have, "backup.age_h") {
			break
		}
		time.Sleep(time.Second)
	}
	have := strings.Join(names.Names, ",")
	for _, want := range []string{"cpu.cpu_p", "cpu.user_p", "mem.Mem.used", "backup.age_h"} {
		if !strings.Contains(have, want) {
			t.Fatalf("F1 series %q missing; have %s\nfluent-bit:\n%s", want, have, out)
		}
	}
	if strings.Contains(have, "cpu0") {
		t.Errorf("F2 per-core series not filtered: %s", have)
	}
	var logs struct {
		Logs []struct {
			Host, Service, Msg string
			Level              int
		}
	}
	r.get(t, "/api/v1/logs?host=fb-e2e&service=api", &logs)
	if len(logs.Logs) == 0 || logs.Logs[0].Level != 3 || logs.Logs[0].Msg != "payment failed" {
		t.Fatalf("F3 log lines: %+v", logs)
	}
	var hosts struct {
		Hosts []struct{ Host, Role, Status string }
	}
	r.get(t, "/api/v1/hosts", &hosts)
	found := false
	for _, h := range hosts.Hosts {
		found = found || (h.Host == "fb-e2e" && h.Role == "api")
	}
	if !found {
		t.Fatalf("F4 host with role: %+v", hosts)
	}
	// F5: lograte rule (2 errors per minute) fires from real Fluent Bit traffic
	r.notifier.waitFor(t, "[WARNING] uat/fb-e2e")

	// F6: loglantern down for a while → Fluent Bit buffers and replays; no gap in the log lines
	addr := strings.TrimPrefix(r.ingest, "http://")
	r.stop()
	stopped = true
	down := time.Now()
	time.Sleep(5 * time.Second)
	up := time.Now()
	r2 := startOn(t, db, addr)
	defer r2.stop()
	deadline = time.Now().Add(60 * time.Second)
	for {
		var during struct{ Logs []struct{ Msg string } }
		r2.get(t, fmt.Sprintf("/api/v1/logs?host=fb-e2e&service=api&from=%d&to=%d&limit=1000", down.Unix()+1, up.Unix()-1), &during)
		// 2 lines/s for ~3 s inside the outage window
		if len(during.Logs) >= 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("F6 lines from the outage not replayed: %d\nfluent-bit:\n%s", len(during.Logs), out)
		}
		time.Sleep(time.Second)
	}
}
