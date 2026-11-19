// Package email delivers events by SMTP.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/version"
	"github.com/tntrock/certower/pkg/plugin"
)

func init() {
	plugin.Default.Register(func() plugin.Plugin { return &Notifier{} })
}

// Config configures an SMTP relay and recipients.
type Config struct {
	Host     string   `json:"host"`
	Port     int      `json:"port,omitempty"` // default 587
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// Security is "starttls" (default), "tls" (implicit, usually port 465)
	// or "none" (only for relays on a trusted network).
	Security    string   `json:"security,omitempty"`
	Events      []string `json:"events,omitempty"`
	MinSeverity string   `json:"minSeverity,omitempty"`
}

const configSchema = `{
  "type": "object",
  "required": ["host", "from", "to"],
  "properties": {
    "host": {"type": "string", "title": "SMTP host"},
    "port": {"type": "integer", "minimum": 1, "title": "Port (default 587)"},
    "security": {"type": "string", "enum": ["starttls", "tls", "none"], "title": "Security"},
    "username": {"type": "string", "title": "Username"},
    "password": {"type": "string", "title": "Password", "x-secret": true},
    "from": {"type": "string", "format": "email", "title": "From address"},
    "to": {"type": "array", "items": {"type": "string"}, "title": "Recipients"},
    "events": {"type": "array", "items": {"type": "string"}, "title": "Only these events (default: all)"},
    "minSeverity": {"type": "string", "enum": ["info", "warning", "critical"], "title": "Minimum severity"}
  }
}`

// Notifier sends one email per event.
type Notifier struct{ cfg Config }

func (n *Notifier) Meta() plugin.Meta {
	return plugin.Meta{
		Name:         "email",
		Kind:         plugin.KindNotifier,
		Version:      version.Version,
		Description:  "Email through an SMTP relay.",
		RunsOn:       plugin.RunsOnServer,
		ConfigSchema: json.RawMessage(configSchema),
	}
}

func (n *Notifier) Configure(_ context.Context, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if cfg.Host == "" {
		return errors.New("email: host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	switch cfg.Security {
	case "":
		cfg.Security = "starttls"
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("email: unknown security %q", cfg.Security)
	}
	if _, err := mail.ParseAddress(cfg.From); err != nil {
		return fmt.Errorf("email: from: %w", err)
	}
	if len(cfg.To) == 0 {
		return errors.New("email: at least one recipient is required")
	}
	for _, to := range cfg.To {
		if _, err := mail.ParseAddress(to); err != nil {
			return fmt.Errorf("email: recipient %q: %w", to, err)
		}
	}
	n.cfg = cfg
	return nil
}

// message builds the RFC 5322 message.
func (n *Notifier) message(e plugin.Event) []byte {
	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", n.cfg.From)
	header("To", strings.Join(n.cfg.To, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", "[Certower] "+e.Subject))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	header("X-Certower-Event", string(e.Type))
	b.WriteString("\r\n")
	body := e.Body
	if e.Link != "" {
		body += "\n\n" + e.Link
	}
	body += fmt.Sprintf("\n\n--\nCertower %s · severity %s · %s\n", version.Version, e.Severity, e.Time.Format(time.RFC3339))
	// Normalize line endings and dot-stuffing is handled by net/smtp.
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return b.Bytes()
}

func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	addr := net.JoinHostPort(n.cfg.Host, strconv.Itoa(n.cfg.Port))
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{ServerName: n.cfg.Host, MinVersion: tls.VersionTLS12}
	if n.cfg.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(time.Minute))
	}
	c, err := smtp.NewClient(conn, n.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("email: %w", err)
	}
	defer c.Close()
	if n.cfg.Security == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("email: STARTTLS: %w", err)
		}
	}
	if n.cfg.Username != "" {
		// PlainAuth refuses to send credentials without TLS, except to
		// localhost.
		if err := c.Auth(smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}
	from, _ := mail.ParseAddress(n.cfg.From)
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	for _, to := range n.cfg.To {
		addr, _ := mail.ParseAddress(to)
		if err := c.Rcpt(addr.Address); err != nil {
			return fmt.Errorf("email: recipient %s: %w", addr.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if _, err := w.Write(n.message(e)); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return c.Quit()
}
