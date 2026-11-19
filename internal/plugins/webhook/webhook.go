// Package webhook delivers events as HTTP POSTs: the full JSON event, or a
// chat message for Slack-compatible ({"text"}) or Discord ({"content"})
// incoming webhooks.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/version"
	"github.com/tntrock/certower/pkg/plugin"
)

func init() {
	plugin.Default.Register(func() plugin.Plugin { return &Notifier{} })
}

// Config configures one webhook.
type Config struct {
	URL string `json:"url"`
	// Format is "json" (default), "slack" or "discord".
	Format string `json:"format,omitempty"`
	// Secret signs JSON deliveries: X-Certower-Signature is
	// "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)).
	Secret string `json:"secret,omitempty"`
	// Events and MinSeverity are applied by the server before delivery.
	Events      []string `json:"events,omitempty"`
	MinSeverity string   `json:"minSeverity,omitempty"`
}

const configSchema = `{
  "type": "object",
  "required": ["url"],
  "properties": {
    "url": {"type": "string", "format": "uri", "title": "Webhook URL", "x-secret": true},
    "format": {"type": "string", "enum": ["json", "slack", "discord"], "title": "Format"},
    "secret": {"type": "string", "title": "Signing secret (json format)", "x-secret": true},
    "events": {"type": "array", "items": {"type": "string"}, "title": "Only these events (default: all)"},
    "minSeverity": {"type": "string", "enum": ["info", "warning", "critical"], "title": "Minimum severity"}
  }
}`

// Notifier posts events to a URL.
type Notifier struct {
	cfg    Config
	client *http.Client
}

func (n *Notifier) Meta() plugin.Meta {
	return plugin.Meta{
		Name:         "webhook",
		Kind:         plugin.KindNotifier,
		Version:      version.Version,
		Description:  "HTTP POST of each event: signed JSON, or a chat message for Slack, Mattermost, Google Chat or Discord.",
		RunsOn:       plugin.RunsOnServer,
		ConfigSchema: json.RawMessage(configSchema),
	}
}

func (n *Notifier) Configure(_ context.Context, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("webhook: url must be an http(s) URL")
	}
	switch cfg.Format {
	case "", "json", "slack", "discord":
	default:
		return fmt.Errorf("webhook: unknown format %q", cfg.Format)
	}
	n.cfg = cfg
	n.client = &http.Client{Timeout: 15 * time.Second}
	return nil
}

// Text renders an event as a short chat message.
func Text(e plugin.Event) string {
	icon := map[plugin.Severity]string{plugin.SeverityInfo: "ℹ️", plugin.SeverityWarning: "⚠️", plugin.SeverityCritical: "🚨"}[e.Severity]
	var b strings.Builder
	fmt.Fprintf(&b, "%s *%s*", icon, e.Subject)
	if e.Body != "" {
		b.WriteString("\n" + e.Body)
	}
	if e.Link != "" {
		b.WriteString("\n" + e.Link)
	}
	return b.String()
}

func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	var body []byte
	var err error
	switch n.cfg.Format {
	case "slack":
		body, err = json.Marshal(map[string]string{"text": Text(e)})
	case "discord":
		body, err = json.Marshal(map[string]string{"content": strings.ReplaceAll(Text(e), "*", "**")})
	default:
		body, err = json.Marshal(e)
	}
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certower/"+version.Version)
	req.Header.Set("X-Certower-Event", string(e.Type))
	if n.cfg.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-Certower-Timestamp", ts)
		req.Header.Set("X-Certower-Signature", "sha256="+Sign(n.cfg.Secret, ts, body))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("webhook: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Sign computes the signature receivers check: hex HMAC-SHA256 over
// timestamp + "." + body. Receivers should also reject old timestamps.
func Sign(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}
