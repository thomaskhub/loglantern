package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// SIGHUP applies a new config without dropping ingest; a broken config is rejected.
func TestReload(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	var mu sync.Mutex
	var hooks []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		hooks = append(hooks, b["text"])
		mu.Unlock()
	}))
	defer hook.Close()
	waitHook := func(sub string) {
		t.Helper()
		for range 200 {
			mu.Lock()
			all := strings.Join(hooks, "\n")
			mu.Unlock()
			if strings.Contains(all, sub) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("no webhook message with %q; got %q", sub, hooks)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "loglantern")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/loglantern").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ip, ap := freePort(t), freePort(t)
	cfgPath := filepath.Join(dir, "c.yaml")
	write := func(threshold string) {
		_ = os.WriteFile(cfgPath, []byte(fmt.Sprintf(`listen: {ingest: "127.0.0.1:%d", api: "127.0.0.1:%d"}
storage: {path: %q}
envs: {uat: {ingest_token_env: LL_TOKEN}}
tick: 200ms
rules: [{name: cpu, type: threshold, series: cpu.cpu_p, op: ">", value: "%s"}]
routes: [{name: all, send: [hook]}]
notifiers: {hook: {webhook: {url_env: LL_HOOK}}}
`, ip, ap, filepath.Join(dir, "ll.db"), threshold)), 0o644)
	}
	write("90")
	cmd := exec.Command(bin, "-config", cfgPath)
	cmd.Env = append(os.Environ(), "LL_TOKEN=tok", "LL_HOOK="+hook.URL)
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	waitUp(t, fmt.Sprintf("127.0.0.1:%d", ip))

	var sent, failed atomic.Int64
	// like Fluent Bit, retry once when a keep-alive connection is closed by the old generation
	post := func(v float64) {
		b, _ := json.Marshal([]map[string]any{{"host": "h1", "kind": "metric", "source": "cpu", "cpu_p": v}})
		var resp *http.Response
		var err error
		for try := 0; try < 2; try++ {
			req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/", ip), bytes.NewReader(b))
			req.Header.Set("Authorization", "Bearer tok")
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
		}
		if err != nil || resp.StatusCode != 204 {
			failed.Add(1)
			if resp != nil {
				t.Logf("post status %d", resp.StatusCode)
				resp.Body.Close()
			} else {
				t.Logf("post error: %v", err)
			}
			return
		}
		resp.Body.Close()
		sent.Add(1)
	}
	post(80)
	time.Sleep(500 * time.Millisecond)

	// lower the threshold and reload while records keep coming
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				post(80)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()
	write("70")
	_ = cmd.Process.Signal(syscall.SIGHUP)
	waitHook("[WARNING] uat/h1") // 80 > 70 with the new rule
	close(stop)
	wg.Wait()
	if failed.Load() > 0 {
		t.Errorf("R1 %d of %d posts failed during reload", failed.Load(), sent.Load()+failed.Load())
	}
	if !strings.Contains(stderr.String(), "config reloaded") {
		t.Errorf("R1 no reload log:\n%s", stderr.String())
	}

	// R2 a broken config is rejected and the old one keeps running
	_ = os.WriteFile(cfgPath, []byte("rules: [{name: x, type: nope}]\n"), 0o644)
	_ = cmd.Process.Signal(syscall.SIGHUP)
	time.Sleep(500 * time.Millisecond)
	if !strings.Contains(stderr.String(), "reload rejected") {
		t.Fatalf("R2 not rejected:\n%s", stderr.String())
	}
	post(10)
	waitHook("[RESOLVED] uat/h1")
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
