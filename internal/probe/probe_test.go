package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
)

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			time.Sleep(300 * time.Millisecond)
		case "/down":
			w.WriteHeader(502)
		case "/moved":
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "status: healthy")
	}))
	defer srv.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := config.Probe{Env: "uat", Host: "web", Timeout: config.Duration(100 * time.Millisecond), ExpectStatus: 200}
	for _, tc := range []struct {
		name, path, contains string
		up                   float64
		status               string
	}{
		{"ok", "/ok", "healthy", 1, "ok"},
		{"text", "/ok", "nope", 0, "body lacks expected text"},
		{"down", "/down", "", 0, "status 502 Bad Gateway"},
		{"moved", "/moved", "", 0, "status 302 Found"},
		{"slow", "/slow", "", 0, "error: context deadline exceeded"},
	} {
		p := base
		p.Name, p.URL, p.Contains = tc.name, srv.URL+tc.path, tc.contains
		r := Check(context.Background(), c, p, time.Now)
		if r.Values["probe."+tc.name+".up"] != tc.up || !strings.HasPrefix(r.Texts["probe."+tc.name+".status"], tc.status) || !r.Synthetic || r.Host != "web" {
			t.Errorf("B1 %s: %+v", tc.name, r)
		}
	}
	p := base
	p.Name, p.URL, p.Host = "x", "http://127.0.0.1:1/", ""
	if r := Check(context.Background(), c, p, time.Now); r.Values["probe.x.up"] != 0 || r.Host != "probe" || strings.Contains(r.Texts["probe.x.status"], "127.0.0.1:1/\"") {
		t.Errorf("B2 refused: %+v", r)
	}
}
