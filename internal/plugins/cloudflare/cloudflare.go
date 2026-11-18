// Package cloudflare solves ACME DNS-01 challenges with the Cloudflare API.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	lego "github.com/go-acme/lego/v4/providers/dns/cloudflare"

	"github.com/tntrock/certower/internal/version"
	"github.com/tntrock/certower/pkg/plugin"
)

func init() {
	plugin.Default.Register(func() plugin.Plugin { return &Solver{} })
}

// Config uses a scoped API token. Create it in the Cloudflare dashboard with
// "Zone:Read" and "DNS:Edit" on the zones Certower should manage.
type Config struct {
	APIToken string `json:"apiToken"`
	// ZoneToken optionally separates zone lookup from DNS edits: APIToken
	// then needs only "DNS:Edit" and ZoneToken "Zone:Read".
	ZoneToken string `json:"zoneToken,omitempty"`
	// PropagationTimeoutSeconds bounds the wait for records to appear.
	PropagationTimeoutSeconds int `json:"propagationTimeoutSeconds,omitempty"`
}

const configSchema = `{
  "type": "object",
  "required": ["apiToken"],
  "properties": {
    "apiToken": {"type": "string", "title": "API token (Zone:Read, DNS:Edit)", "x-secret": true},
    "zoneToken": {"type": "string", "title": "Separate Zone:Read token", "x-secret": true},
    "propagationTimeoutSeconds": {"type": "integer", "minimum": 10, "title": "Propagation timeout (seconds)"}
  }
}`

// Solver wraps lego's Cloudflare provider.
type Solver struct {
	p *lego.DNSProvider
}

func (s *Solver) Meta() plugin.Meta {
	return plugin.Meta{
		Name:         "cloudflare",
		Kind:         plugin.KindDNS,
		Version:      version.Version,
		Description:  "Cloudflare DNS, authenticated with a scoped API token.",
		RunsOn:       plugin.RunsOnServer,
		ConfigSchema: json.RawMessage(configSchema),
	}
}

func (s *Solver) Configure(ctx context.Context, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	if cfg.APIToken == "" {
		return errors.New("cloudflare: apiToken is required")
	}
	lc := lego.NewDefaultConfig()
	lc.AuthToken = cfg.APIToken
	lc.ZoneToken = cfg.ZoneToken
	if cfg.PropagationTimeoutSeconds > 0 {
		lc.PropagationTimeout = time.Duration(cfg.PropagationTimeoutSeconds) * time.Second
	}
	p, err := lego.NewDNSProviderConfig(lc)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	s.p = p
	return nil
}

func (s *Solver) Present(domain, token, keyAuth string) error {
	if s.p == nil {
		return errors.New("cloudflare: not configured")
	}
	return s.p.Present(domain, token, keyAuth)
}

func (s *Solver) CleanUp(domain, token, keyAuth string) error {
	if s.p == nil {
		return errors.New("cloudflare: not configured")
	}
	return s.p.CleanUp(domain, token, keyAuth)
}

// Timeout passes Cloudflare's propagation settings through to lego.
func (s *Solver) Timeout() (timeout, interval time.Duration) {
	return s.p.Timeout()
}
