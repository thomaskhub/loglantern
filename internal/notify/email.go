package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Email sends plain-text mail over SMTP (STARTTLS, implicit TLS, or none for a local relay).
type Email struct {
	Host          string
	Port          int
	TLS           string // starttls | tls | none
	User          string
	Password      string
	From          string
	To            []string
	Targets       map[string][]string
	SubjectPrefix string
	TLSConfig     *tls.Config // tests
}

// Send mails text; the subject is the first line.
func (e *Email) Send(ctx context.Context, target, text string) error {
	to := e.To
	if target != "" {
		var ok bool
		if to, ok = e.Targets[target]; !ok {
			return fmt.Errorf("email: unknown target %q", target)
		}
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	tcfg := e.TLSConfig
	if tcfg == nil {
		tcfg = &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if e.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: tcfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("email: %w", err)
	}
	defer c.Close()
	if e.TLS == "starttls" {
		if err := c.StartTLS(tcfg); err != nil {
			return fmt.Errorf("email: starttls: %w", err)
		}
	}
	if e.User != "" {
		// PlainAuth refuses to send the password without TLS (except to localhost)
		if err := c.Auth(smtp.PlainAuth("", e.User, e.Password, e.Host)); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}
	if err := c.Mail(e.From); err != nil {
		return fmt.Errorf("email: from: %w", err)
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("email: rcpt %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: data: %w", err)
	}
	if _, err := w.Write(e.message(to, text)); err != nil {
		return fmt.Errorf("email: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return c.Quit()
}

// message builds the RFC 5322 message; header values never contain CR/LF.
func (e *Email) message(to []string, text string) []byte {
	subject, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	if r := []rune(subject); len(r) > 120 {
		subject = string(r[:120]) + "…"
	}
	clean := strings.NewReplacer("\r", " ", "\n", " ")
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := e.From[strings.LastIndex(e.From, "@")+1:]
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", clean.Replace(e.From))
	fmt.Fprintf(&b, "To: %s\r\n", clean.Replace(strings.Join(to, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", clean.Replace(e.SubjectPrefix+" "+subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), clean.Replace(domain))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}
