package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestSlack(t *testing.T) {
	var got []map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		switch r.URL.Path {
		case "/api/chat.postMessage":
			auth = r.Header.Get("Authorization")
			if b["channel"] == "C-LIMIT" {
				w.Header().Set("Retry-After", "9")
				w.WriteHeader(429)
				return
			}
			if b["channel"] == "C-GONE" {
				_, _ = io.WriteString(w, `{"ok":false,"error":"channel_not_found"}`)
				return
			}
			got = append(got, b)
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/hook":
			got = append(got, b)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	s := &Slack{Base: srv.URL, Token: "xoxb-1", Channel: "C-DEF", Channels: map[string]string{"prod": "C-PROD", "limit": "C-LIMIT", "gone": "C-GONE"}}
	if err := s.Send(ctx, "prod", "a <b> & c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(ctx, "", "default"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer xoxb-1" || got[0]["channel"] != "C-PROD" || got[0]["text"] != "a &lt;b&gt; &amp; c" || got[1]["channel"] != "C-DEF" {
		t.Fatalf("K1 bot: %v", got)
	}
	if err := s.Send(ctx, "x", "t"); err == nil {
		t.Fatal("K2 unknown channel accepted")
	}
	if err := s.Send(ctx, "gone", "t"); err == nil || !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("K3 api error: %v", err)
	}
	if err := s.Send(ctx, "limit", "t"); err == nil {
		t.Fatal("K4 429")
	} else if ra, ok := err.(*RetryAfter); !ok || ra.Wait.Seconds() != 9 {
		t.Fatalf("K4 retry-after: %v", err)
	}
	wh := &Slack{WebhookURL: srv.URL + "/hook"}
	if err := wh.Send(ctx, "", "via hook"); err != nil || got[2]["text"] != "via hook" {
		t.Fatalf("K5 webhook: %v %v", err, got)
	}
}

// fakeSMTP is a minimal SMTP server without TLS (tls: none) that records one session per message.
type fakeSMTP struct {
	mu   sync.Mutex
	from string
	rcpt []string
	data string
	ln   net.Listener
}

func (f *fakeSMTP) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.session(c)
	}
}

func (f *fakeSMTP) session(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	say("220 fake")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250-fake\r\n250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from, f.rcpt = addr(line), nil
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, addr(line))
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func addr(line string) string {
	_, a, _ := strings.Cut(line, "<")
	a, _, _ = strings.Cut(a, ">")
	return a
}

func TestEmail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f := &fakeSMTP{ln: ln}
	go f.serve()
	port := ln.Addr().(*net.TCPAddr).Port
	e := &Email{Host: "127.0.0.1", Port: port, TLS: "none", From: "alerts@example.org", To: []string{"ops@example.org"},
		Targets: map[string][]string{"mgmt": {"a@example.org", "b@example.org"}}, SubjectPrefix: "[ll]"}
	ctx := context.Background()
	if err := e.Send(ctx, "", "[CRITICAL] prod/db1 #3: disk 91 %\r\nInjected: header\nsecond line"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	data, from, rcpt := f.data, f.from, strings.Join(f.rcpt, ",")
	f.mu.Unlock()
	if from != "alerts@example.org" || rcpt != "ops@example.org" {
		t.Fatalf("M1 envelope: %s %s", from, rcpt)
	}
	head, body, _ := strings.Cut(data, "\r\n\r\n")
	if !strings.Contains(head, "Subject: [ll] [CRITICAL] prod/db1 #3: disk 91 %") || strings.Contains(head, "Injected") || !strings.Contains(head, "Auto-Submitted: auto-generated") {
		t.Fatalf("M2 headers:\n%s", head)
	}
	if !strings.Contains(body, "second line") {
		t.Fatalf("M3 body: %q", body)
	}
	if err := e.Send(ctx, "mgmt", "x"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	rcpt = strings.Join(f.rcpt, ",")
	f.mu.Unlock()
	if rcpt != "a@example.org,b@example.org" {
		t.Fatalf("M4 target recipients: %s", rcpt)
	}
	if err := e.Send(ctx, "nope", "x"); err == nil {
		t.Fatal("M5 unknown target accepted")
	}
}

func TestEmailUTF8Subject(t *testing.T) {
	e := &Email{From: "a@example.org", SubjectPrefix: "[ll]"}
	msg := string(e.message([]string{"b@example.org"}, "Größe über Grenze\nbody"))
	if !strings.Contains(msg, "Subject: =?utf-8?q?") {
		t.Fatalf("M7 encoded subject:\n%s", msg)
	}
}
