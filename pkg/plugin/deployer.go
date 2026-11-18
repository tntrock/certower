package plugin

import (
	"context"
	"encoding/json"
)

// Bundle is what gets installed on a target.
type Bundle struct {
	// CertPEM is the leaf certificate.
	CertPEM []byte
	// ChainPEM holds the intermediates, without the root.
	ChainPEM []byte
	// KeyPEM is set only for server-side connectors. Agent deployers get an
	// empty KeyPEM and use the key the agent generated locally, at KeyPath.
	KeyPEM  []byte
	KeyPath string
	// Fingerprint is the hex SHA-256 of the leaf certificate's DER.
	Fingerprint string
}

// Target is one configured deployment destination.
type Target struct {
	ID     string
	Config json.RawMessage
}

// DeployResult reports what a deployment did, so it can be undone.
type DeployResult struct {
	// RollbackState is opaque to the host and handed back to Rollback.
	RollbackState json.RawMessage
	Message       string
}

// Deployer installs certificates on targets.
type Deployer interface {
	Plugin
	Deploy(ctx context.Context, target Target, bundle Bundle) (*DeployResult, error)
	// Verify checks that the target is actually serving the certificate with
	// the given fingerprint. A deployment only counts as done after Verify
	// succeeds.
	Verify(ctx context.Context, target Target, fingerprint string) error
	// Rollback restores the state from before Deploy.
	Rollback(ctx context.Context, target Target, state json.RawMessage) error
}
