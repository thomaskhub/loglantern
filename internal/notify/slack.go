package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Slack posts with a bot token (chat.postMessage) or to an incoming webhook.
type Slack struct {
	Base       string // https://slack.com
	Token      string
	WebhookURL string
	Channel    string            // default channel id
	Channels   map[string]string // target → channel id
	Client     *http.Client
}

// slackText escapes the three characters Slack treats as markup.
func slackText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(cut(s))
}

// Send posts plain text.
func (s *Slack) Send(ctx context.Context, target, text string) error {
	if s.WebhookURL != "" {
		resp, err := post(ctx, s.Client, s.WebhookURL, map[string]string{"text": slackText(text)})
		if err != nil {
			return errors.New("slack: request failed") // the URL is a secret
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return slackStatus(resp, true)
	}
	ch := s.Channel
	if target != "" {
		var ok bool
		if ch, ok = s.Channels[target]; !ok {
			return fmt.Errorf("slack: unknown channel %q", target)
		}
	}
	b, _ := json.Marshal(map[string]any{"channel": ch, "text": slackText(text), "unfurl_links": false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.Base, "/")+"/api/chat.postMessage", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.Token)
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("slack: request failed")
	}
	defer resp.Body.Close()
	if err := slackStatus(resp, false); err != nil {
		return err
	}
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r)
	if !r.OK {
		return fmt.Errorf("slack: %s", r.Error)
	}
	return nil
}

func slackStatus(resp *http.Response, webhook bool) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
			return &RetryAfter{Wait: time.Duration(n) * time.Second, Err: errors.New("slack: rate limited")}
		}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slack: status %d", resp.StatusCode)
	}
	return nil
}
