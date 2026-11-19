package plugins_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/plugins/email"
	"github.com/tntrock/certower/internal/plugins/webhook"
	"github.com/tntrock/certower/pkg/plugin"
)

var event = plugin.Event{
	Type: plugin.EventCertExpiring, Severity: plugin.SeverityWarning, Time: time.Now(),
	Org: "acme", Project: "web", Subject: "www expires in 7 days", Body: "Renewal has failed twice.", Link: "https://certower.example.com/o/acme/p/web/certificates/www",
}

func configure(t *testing.T, p plugin.Plugin, cfg any) {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	if err := p.Configure(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookSignedJSON(t *testing.T) {
	var got struct {
		body      []byte
		sig, ts   string
		eventType string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.sig, got.ts, got.eventType = r.Header.Get("X-Certower-Signature"), r.Header.Get("X-Certower-Timestamp"), r.Header.Get("X-Certower-Event")
	}))
	defer srv.Close()
	n := &webhook.Notifier{}
	configure(t, n, webhook.Config{URL: srv.URL, Secret: "s3cret"})
	if err := n.Notify(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if got.sig != "sha256="+webhook.Sign("s3cret", got.ts, got.body) || got.eventType != "cert.expiring" {
		t.Fatalf("signature %q, event %q", got.sig, got.eventType)
	}
	var e plugin.Event
	if err := json.Unmarshal(got.body, &e); err != nil || e.Subject != event.Subject {
		t.Fatalf("body = %s", got.body)
	}
}

func TestWebhookSlackAndErrors(t *testing.T) {
	var body map[string]string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(status)
		io.WriteString(w, "no_text")
	}))
	defer srv.Close()
	n := &webhook.Notifier{}
	configure(t, n, webhook.Config{URL: srv.URL, Format: "slack"})
	if err := n.Notify(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["text"], "*www expires in 7 days*") || !strings.Contains(body["text"], event.Link) {
		t.Fatalf("slack text = %q", body["text"])
	}
	status = http.StatusBadRequest
	if err := n.Notify(context.Background(), event); err == nil || !strings.Contains(err.Error(), "no_text") {
		t.Fatalf("error not surfaced: %v", err)
	}
	if err := (&webhook.Notifier{}).Configure(context.Background(), []byte(`{"url":"ftp://x"}`)); err == nil {
		t.Fatal("ftp URL accepted")
	}
}

// fakeSMTP accepts one message and returns it on the channel.
func fakeSMTP(t *testing.T) (addr string, msgs chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	msgs = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { io.WriteString(c, s+"\r\n") }
		say("220 fake ESMTP")
		var rcpts []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				say("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO"):
				rcpts = append(rcpts, strings.TrimSpace(line[8:]))
				say("250 ok")
			case cmd == "DATA":
				say("354 go ahead")
				var b strings.Builder
				for {
					l, _ := r.ReadString('\n')
					if l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				msgs <- "RCPT " + strings.Join(rcpts, ",") + "\n" + b.String()
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("502 unsupported")
			}
		}
	}()
	return ln.Addr().String(), msgs
}

func TestEmail(t *testing.T) {
	addr, msgs := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	n := &email.Notifier{}
	configure(t, n, email.Config{Host: host, Port: p, Security: "none", From: "Certower <certower@example.com>", To: []string{"ops@example.com", "sec@example.com"}})
	if err := n.Notify(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	msg := <-msgs
	for _, want := range []string{"ops@example.com", "sec@example.com", "Subject: [Certower] www expires in 7 days", "Renewal has failed twice.", event.Link} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if err := (&email.Notifier{}).Configure(context.Background(), []byte(`{"host":"smtp","from":"x@example.com","to":["not an address"]}`)); err == nil {
		t.Error("bad recipient accepted")
	}
}
