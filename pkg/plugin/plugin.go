// Package plugin defines the extension points of Certower.
//
// There are four plugin kinds: Issuer, DNSSolver, Deployer and Notifier.
// Built-in plugins register themselves with a Registry at init time.
// Out-of-tree plugins are served over gRPC and wrapped to these same
// interfaces by the host.
package plugin

import (
	"context"
	"encoding/json"
)

// Kind identifies which interface a plugin implements.
type Kind string

const (
	KindIssuer   Kind = "issuer"
	KindDNS      Kind = "dns"
	KindDeployer Kind = "deployer"
	KindNotifier Kind = "notifier"
)

// RunsOn says where a plugin executes.
type RunsOn string

const (
	// RunsOnServer plugins execute inside the certower server process.
	RunsOnServer RunsOn = "server"
	// RunsOnAgent plugins execute inside certower-agent on the target host.
	RunsOnAgent RunsOn = "agent"
)

// Meta describes a plugin. ConfigSchema is a JSON Schema document that the
// UI renders as a form and the host validates before calling Configure.
type Meta struct {
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	Version     string `json:"version"`
	Description string `json:"description"`
	RunsOn      RunsOn `json:"runsOn"`
	// RequiresDNS marks issuers that cannot issue without a DNS provider
	// (ACME with DNS-01).
	RequiresDNS  bool            `json:"requiresDns,omitempty"`
	ConfigSchema json.RawMessage `json:"configSchema,omitempty"`
}

// ConfigPreparer is implemented by plugins that fill in generated fields,
// such as an ACME account key, when a configuration is first created. The
// result is stored, so it must be deterministic thereafter.
type ConfigPreparer interface {
	PrepareConfig(ctx context.Context, config json.RawMessage) (json.RawMessage, error)
}

// Plugin is the common part of every plugin.
type Plugin interface {
	Meta() Meta
	// Configure is called once per configured instance with config that has
	// already passed ConfigSchema validation. Secret fields are resolved by
	// the host before the call; plugins never see secret references.
	Configure(ctx context.Context, config json.RawMessage) error
}
