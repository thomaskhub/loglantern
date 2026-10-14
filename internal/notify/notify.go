// Package notify delivers outbox messages to Telegram and webhooks.
package notify

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/store"
)

// Notifier sends one text to a target (e.g. a Telegram topic name).
type Notifier interface {
	Send(ctx context.Context, target, text string) error
}

// ImageNotifier is a Notifier that can also send a picture (PNG) with a caption.
type ImageNotifier interface {
	SendImage(ctx context.Context, target, caption string, png []byte) error
}

// RetryAfter is returned when the receiver asks to wait.
type RetryAfter struct {
	Wait time.Duration
	Err  error
}

func (e *RetryAfter) Error() string { return fmt.Sprintf("%v (retry after %s)", e.Err, e.Wait) }

// maxText is Telegram's message limit; webhooks get the same cut.
const maxText = 4096

func cut(s string) string {
	if len(s) <= maxText {
		return s
	}
	r := []rune(s)
	for len(string(r)) > maxText-1 {
		r = r[:len(r)-100]
	}
	return string(r) + "…"
}

// Telegram sends with the Bot API; targets map to forum topics.
type Telegram struct {
	Base   string // https://api.telegram.org
	Token  string
	ChatID string
	Topics map[string]int
	Client *http.Client
}

// telegramHTML escapes text for parse_mode HTML and turns ``` fenced blocks into <pre> (monospace tables).
func telegramHTML(s string) string {
	var out strings.Builder
	var buf []string
	inPre := false
	flush := func() {
		if len(buf) == 0 {
			return
		}
		t := html.EscapeString(strings.Join(buf, "\n"))
		if inPre {
			out.WriteString("<pre>" + t + "</pre>\n")
		} else {
			out.WriteString(t + "\n")
		}
		buf = nil
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "```" {
			flush()
			inPre = !inPre
			continue
		}
		buf = append(buf, line)
	}
	flush()
	return strings.TrimRight(out.String(), "\n")
}

var (
	reAlert    = regexp.MustCompile(`(?s)^\[([A-Za-z]+)\] (\S+/\S+) #(\d+): (.*)$`)
	reResolved = regexp.MustCompile(`(?s)^\[RESOLVED\] (\S+/\S+) #(\d+) after (\S+): (.*)$`)
	reStill    = regexp.MustCompile(`(?s)^\[STILL OPEN (\S+)\] (\S+/\S+) #(\d+): (.*)$`)
	reAI       = regexp.MustCompile(`(?s)^\[AI ([^\]]+)\] (\S+/\S+) #(\d+): (.*)$`)
	reSince    = regexp.MustCompile(`^(.*) \(open since (\S+)\)$`)
)

// telegramLayout turns the one-line incident messages ("[CRIT] env/host #7: text") into a bold header line and a body that
// breaks at "; ", so long rule text stays readable. Other messages (status, daily, free text) come back unchanged.
// Only the Telegram notifier uses it: the stored text, webhooks, Slack and e-mail keep the one-line form.
func telegramLayout(s string) (header, body string) {
	sep := " \u00b7 "
	if m := reResolved.FindStringSubmatch(s); m != nil {
		return "\u2705 resolved after " + m[3] + sep + m[1] + sep + "#" + m[2], wrapText(m[4])
	}
	if m := reStill.FindStringSubmatch(s); m != nil {
		return "\u23f0 still open " + m[1] + sep + m[2] + sep + "#" + m[3], wrapText(m[4])
	}
	if m := reAI.FindStringSubmatch(s); m != nil {
		return "\U0001F916 " + m[1] + sep + m[2] + sep + "#" + m[3], m[4]
	}
	if m := reAlert.FindStringSubmatch(s); m != nil {
		icon := "\u26aa"
		switch strings.ToUpper(m[1]) {
		case "CRIT", "CRITICAL":
			icon = "\U0001F534"
		case "WARN", "WARNING":
			icon = "\U0001F7E0"
		case "INFO":
			icon = "\U0001F535"
		}
		head, text := icon+" "+strings.ToUpper(m[1])+sep+m[2]+sep+"#"+m[3], m[4]
		if sm := reSince.FindStringSubmatch(text); sm != nil {
			head, text = head+sep+"open since "+sm[2], sm[1]
		}
		return head, wrapText(text)
	}
	return "", s
}

// wrapText puts each "; " part of a long one-line text on its own line.
func wrapText(s string) string {
	if len(s) <= 80 || strings.Contains(s, "\n") {
		return s
	}
	return strings.ReplaceAll(s, "; ", "\n")
}

// telegramText is the HTML text of one message: bold header (incident messages) and the escaped body.
func telegramText(s string) string {
	head, body := telegramLayout(s)
	if head == "" {
		return telegramHTML(s)
	}
	return "<b>" + html.EscapeString(head) + "</b>\n" + telegramHTML(body)
}

// Send posts a message; ``` fenced blocks are sent as monospace.
func (t *Telegram) Send(ctx context.Context, target, text string) error {
	body := map[string]any{"chat_id": t.ChatID, "text": telegramText(cut(text)), "parse_mode": "HTML", "disable_web_page_preview": true}
	if target != "" {
		id, ok := t.Topics[target]
		if !ok {
			return fmt.Errorf("telegram: unknown topic %q", target)
		}
		body["message_thread_id"] = id
	}
	resp, err := post(ctx, t.Client, strings.TrimRight(t.Base, "/")+"/bot"+t.Token+"/sendMessage", body)
	if err != nil {
		return errors.New("telegram: request failed") // the URL holds the token: never log it
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r)
	if resp.StatusCode == http.StatusTooManyRequests && r.Parameters.RetryAfter > 0 {
		return &RetryAfter{Wait: time.Duration(r.Parameters.RetryAfter) * time.Second, Err: errors.New("telegram: rate limited")}
	}
	if resp.StatusCode != http.StatusOK || !r.OK {
		return fmt.Errorf("telegram: %d %s", resp.StatusCode, r.Description)
	}
	return nil
}

// SendImage sends a PNG with a caption to a topic (sendPhoto).
func (t *Telegram) SendImage(ctx context.Context, target, caption string, png []byte) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", t.ChatID)
	if target != "" {
		id, ok := t.Topics[target]
		if !ok {
			return fmt.Errorf("telegram: unknown topic %q", target)
		}
		_ = mw.WriteField("message_thread_id", strconv.Itoa(id))
	}
	_ = mw.WriteField("caption", cut(caption))
	fw, err := mw.CreateFormFile("photo", "chart.png")
	if err != nil {
		return err
	}
	if _, err := fw.Write(png); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(t.Base, "/")+"/bot"+t.Token+"/sendPhoto", &buf)
	if err != nil {
		return errors.New("telegram: request failed")
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c := t.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("telegram: request failed") // the URL holds the token: never log it
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r)
	if resp.StatusCode == http.StatusTooManyRequests && r.Parameters.RetryAfter > 0 {
		return &RetryAfter{Wait: time.Duration(r.Parameters.RetryAfter) * time.Second, Err: errors.New("telegram: rate limited")}
	}
	if resp.StatusCode != http.StatusOK || !r.OK {
		return fmt.Errorf("telegram: %d %s", resp.StatusCode, r.Description)
	}
	return nil
}

// Webhook posts {"text", "target"} as JSON.
type Webhook struct {
	URL    string
	Client *http.Client
}

// Send posts the message.
func (w *Webhook) Send(ctx context.Context, target, text string) error {
	resp, err := post(ctx, w.Client, w.URL, map[string]string{"text": cut(text), "target": target})
	if err != nil {
		return errors.New("webhook: request failed") // the URL may hold a secret
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusTooManyRequests {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			return &RetryAfter{Wait: time.Duration(s) * time.Second, Err: errors.New("webhook: rate limited")}
		}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: status %d", resp.StatusCode)
	}
	return nil
}

func post(ctx context.Context, c *http.Client, url string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c == nil {
		c = http.DefaultClient
	}
	return c.Do(req)
}

// FromConfig builds one notifier per configured name.
func FromConfig(cfg *config.Config) map[string]Notifier {
	client := &http.Client{Timeout: 15 * time.Second}
	out := map[string]Notifier{}
	for name, n := range cfg.Notifiers {
		switch {
		case n.Telegram != nil:
			t := n.Telegram
			out[name] = &Telegram{Base: cmp.Or(t.BaseURL, "https://api.telegram.org"), Token: cfg.Secret(t.TokenEnv), ChatID: t.ChatID, Topics: t.Topics, Client: client}
		case n.Slack != nil:
			sl := n.Slack
			out[name] = &Slack{Base: cmp.Or(sl.BaseURL, "https://slack.com"), Token: cfg.Secret(sl.TokenEnv), WebhookURL: cfg.Secret(sl.WebhookURLEnv),
				Channel: sl.Channel, Channels: sl.Channels, Client: client}
		case n.Email != nil:
			e := n.Email
			out[name] = &Email{Host: e.Host, Port: e.Port, TLS: e.TLS, User: cfg.Secret(e.UserEnv), Password: cfg.Secret(e.PasswordEnv),
				From: e.From, To: e.To, Targets: e.Targets, SubjectPrefix: e.SubjectPrefix}
		case n.Webhook != nil:
			out[name] = &Webhook{URL: cfg.Secret(n.Webhook.URLEnv), Client: client}
		}
	}
	return out
}

// Outbox queues messages for every destination of a route.
type Outbox struct {
	st     *store.Store
	routes map[string]config.Route
}

// NewOutbox creates the queue for the configured routes.
func NewOutbox(st *store.Store, cfg *config.Config) *Outbox {
	o := &Outbox{st: st, routes: map[string]config.Route{}}
	for _, r := range cfg.Routes {
		o.routes[r.Name] = r
	}
	return o
}

// Put queues text on every destination of route; resolved messages are skipped where send_resolved is false.
func (o *Outbox) Put(ctx context.Context, route, text string, incident int64, resolved bool, now time.Time) error {
	r, ok := o.routes[route]
	if !ok {
		return fmt.Errorf("route %q not configured", route)
	}
	if resolved && !r.Resolved() {
		return nil
	}
	for _, d := range r.Send {
		if err := o.st.Enqueue(ctx, route, d, text, incident, now, now.Add(time.Duration(r.Digest))); err != nil {
			return fmt.Errorf("enqueue %s → %s: %w", route, d, err)
		}
	}
	return nil
}

// Sender delivers due outbox messages with exponential backoff; digest routes are sent as one bundle.
type Sender struct {
	Store     *store.Store
	Routes    map[string]config.Route
	Notifiers map[string]Notifier
	Log       *slog.Logger
	Every     time.Duration // poll interval (default 5s)
	Now       func() time.Time
}

// NewSender wires a sender from config.
func NewSender(st *store.Store, cfg *config.Config, n map[string]Notifier, log *slog.Logger) *Sender {
	routes := map[string]config.Route{}
	for _, r := range cfg.Routes {
		routes[r.Name] = r
	}
	return &Sender{Store: st, Routes: routes, Notifiers: n, Log: log}
}

// Backoff after n failed attempts: 30s, 1m, 2m … capped at 30m.
func Backoff(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 0; i < attempts && d < 30*time.Minute; i++ {
		d *= 2
	}
	return min(d, 30*time.Minute)
}

// Run polls until ctx ends; wake triggers an immediate round.
func (s *Sender) Run(ctx context.Context, wake <-chan struct{}) {
	every := s.Every
	if every == 0 {
		every = 5 * time.Second
	}
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		s.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		case <-wake:
		}
	}
}

// digestChunk is the size limit of one bundled message.
const digestChunk = 3500

// Once sends everything due now; returns the number of outbox messages delivered.
func (s *Sender) Once(ctx context.Context) int {
	now := s.now()
	msgs, err := s.Store.Due(ctx, now, 50)
	if err != nil {
		s.Log.Error("outbox", "err", err)
		return 0
	}
	sent := 0
	done := map[string]bool{}    // digest groups handled this round
	blocked := map[string]bool{} // notifiers that asked to wait
	for _, m := range msgs {
		name, _ := config.SplitDest(m.Dest)
		if blocked[name] {
			continue
		}
		batch := [][]store.Message{{m}}
		if r, ok := s.Routes[m.Route]; ok && r.Digest > 0 {
			key := m.Route + "\x00" + m.Dest
			if done[key] {
				continue
			}
			done[key] = true
			group, err := s.Store.Pending(ctx, m.Route, m.Dest)
			if err != nil {
				s.Log.Error("outbox", "err", err)
				continue
			}
			batch = chunks(group)
		}
		for _, b := range batch {
			text := b[0].Text
			if len(b) > 1 || s.Routes[m.Route].Digest > 0 {
				text = digestText(b)
			}
			err := s.send(ctx, m.Dest, text)
			if err == nil {
				for _, x := range b {
					if err := s.Store.MarkSent(ctx, x.ID, s.now()); err != nil {
						s.Log.Error("outbox mark sent", "id", x.ID, "err", err)
					}
				}
				sent += len(b)
				continue
			}
			wait := Backoff(m.Attempts)
			var ra *RetryAfter
			if errors.As(err, &ra) {
				wait = max(ra.Wait, time.Second)
				blocked[name] = true
			}
			s.Log.Warn("send failed", "route", m.Route, "dest", m.Dest, "messages", len(b), "attempt", m.Attempts+1, "retry_in", wait, "err", err)
			for _, x := range b {
				if err := s.Store.MarkFailed(ctx, x.ID, now.Add(wait), err.Error()); err != nil {
					s.Log.Error("outbox mark failed", "id", x.ID, "err", err)
				}
			}
			break // keep the order: the rest of this group waits too
		}
	}
	return sent
}

// chunks splits a digest group into bundles below the size limit.
func chunks(group []store.Message) [][]store.Message {
	var out [][]store.Message
	var cur []store.Message
	size := 0
	for _, m := range group {
		if len(cur) > 0 && size+len(m.Text)+2 > digestChunk {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, m)
		size += len(m.Text) + 2
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func digestText(b []store.Message) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Digest: %d message(s)\n", len(b))
	for _, m := range b {
		sb.WriteString("\n")
		sb.WriteString(m.Text)
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (s *Sender) send(ctx context.Context, dest, text string) error {
	name, target := config.SplitDest(dest)
	n, ok := s.Notifiers[name]
	if !ok {
		return fmt.Errorf("notifier %q not configured", name)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return n.Send(ctx, target, text)
}

// SendImage sends a picture to every destination of route whose notifier can show one (Telegram); the others
// are skipped. It is best effort and not queued: the text of a report is the reliable part.
func (s *Sender) SendImage(ctx context.Context, route, caption string, png []byte) error {
	r, ok := s.Routes[route]
	if !ok {
		return fmt.Errorf("route %q not configured", route)
	}
	var errs []error
	for _, d := range r.Send {
		name, target := config.SplitDest(d)
		in, ok := s.Notifiers[name].(ImageNotifier)
		if !ok {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err := in.SendImage(cctx, target, caption, png)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
