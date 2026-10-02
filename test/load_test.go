package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLoad runs the real binary at 1,000 records/s (A8: under 100 MB RSS, nothing lost).
// LOGLANTERN_LOAD=60s go test -run TestLoad -v ./test/
func TestLoad(t *testing.T) {
	dur, err := time.ParseDuration(os.Getenv("LOGLANTERN_LOAD"))
	if err != nil {
		t.Skip("set LOGLANTERN_LOAD=60s to run")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "loglantern")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/loglantern").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ip, ap := freePort(t), freePort(t)
	cfg := fmt.Sprintf(`listen: {ingest: "127.0.0.1:%d", api: "127.0.0.1:%d"}
storage: {path: %q}
envs: {uat: {ingest_token_env: LL_TOKEN}, prod: {ingest_token_env: LL_TOKEN_PROD}}
tick: 5s
rules:
  - {name: cpu, type: threshold, series: cpu.cpu_p, op: ">", value: "90", for: 2m}
  - {name: rps, type: anomaly, series: app.rps}
  - {name: errors, type: lograte, level: err, count: 50, per: 5m}
  - {name: oom, type: lograte, pattern: "out of memory", count: 1, per: 5m}
routes: [{name: all, notifier: webhook}]
notifiers: {webhook: {url_env: LL_HOOK}}
auth: {api_keys: [{name: dash, key_env: LL_KEY, role: logs}]}
`, ip, ap, filepath.Join(dir, "ll.db"))
	_ = os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(cfg), 0o644)
	cmd := exec.Command(bin, "-config", filepath.Join(dir, "c.yaml"), "-log-level", "warn")
	cmd.Env = append(os.Environ(), "LL_TOKEN=tok-uat", "LL_TOKEN_PROD=tok-prod", "LL_HOOK=http://127.0.0.1:1/", "LL_KEY=dash-key-0123456789")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ingest := fmt.Sprintf("http://127.0.0.1:%d/ingest", ip)
	waitUp(t, fmt.Sprintf("127.0.0.1:%d", ip))

	// 20 hosts × 2 envs; every 100 ms one batch of 100 records: ~80 % logs, 20 % metrics
	sent, busy, maxLat := 0, 0, time.Duration(0)
	tk := time.NewTicker(100 * time.Millisecond)
	defer tk.Stop()
	var peak int
	end := time.Now().Add(dur)
	for n := 0; time.Now().Before(end); n++ {
		<-tk.C
		tok := "tok-uat"
		if n%2 == 1 {
			tok = "tok-prod"
		}
		var batch []map[string]any
		now := float64(time.Now().UnixMilli()) / 1000
		for i := range 100 {
			host := "host-" + strconv.Itoa((n*100+i)%20)
			if i%5 == 0 {
				batch = append(batch, map[string]any{"date": now, "host": host, "kind": "metric", "source": "cpu", "cpu_p": float64(i % 70), "user_p": 1.5})
				continue
			}
			lvl := "6"
			if i%40 == 1 {
				lvl = "3"
			}
			batch = append(batch, map[string]any{"date": now, "host": host, "SYSLOG_IDENTIFIER": "api", "PRIORITY": lvl,
				"MESSAGE": fmt.Sprintf(`{"msg":"request done","path":"/rpc/playlist.get","ms":%d,"user":"u%d@example.com"}`, i, n)})
		}
		b, _ := json.Marshal(batch)
		req, _ := http.NewRequest(http.MethodPost, ingest, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v\n%s", err, stderr.String())
		}
		resp.Body.Close()
		maxLat = max(maxLat, time.Since(start))
		switch resp.StatusCode {
		case 204:
			sent += len(batch)
		case 503:
			busy++
		default:
			t.Fatalf("status %d", resp.StatusCode)
		}
		if n%10 == 0 {
			peak = max(peak, rss(t, cmd.Process.Pid))
		}
	}
	time.Sleep(3 * time.Second) // last flush
	var h struct {
		Written int64 `json:"records_written"`
		Queue   int   `json:"queue"`
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", ap))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	hwm := vmHWM(t, cmd.Process.Pid)
	st, _ := os.Stat(filepath.Join(dir, "ll.db"))
	t.Logf("sent %d records in %s (%.0f/s), busy %d, written %d, max post latency %s, RSS peak %d MB (VmHWM %d MB), db %d MB",
		sent, dur, float64(sent)/dur.Seconds(), busy, h.Written, maxLat, peak>>10, hwm>>10, st.Size()>>20)
	if h.Written != int64(sent) {
		t.Errorf("A8 lost records: sent %d, written %d", sent, h.Written)
	}
	if hwm>>10 >= 100 {
		t.Errorf("A8 RSS %d MB >= 100 MB", hwm>>10)
	}
	if busy > 0 {
		t.Errorf("A8 server busy %d times at 1,000 records/s", busy)
	}
	if strings.Contains(stderr.String(), `"level":"ERROR"`) {
		t.Errorf("errors logged:\n%s", stderr.String())
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitUp(t *testing.T, addr string) {
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server did not start")
}

func statusKB(t *testing.T, pid int, field string) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, field+":") {
			n, _ := strconv.Atoi(strings.Fields(l)[1])
			return n
		}
	}
	return 0
}

func rss(t *testing.T, pid int) int   { return statusKB(t, pid, "VmRSS") }
func vmHWM(t *testing.T, pid int) int { return statusKB(t, pid, "VmHWM") }
