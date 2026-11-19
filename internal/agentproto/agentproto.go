// Package agentproto defines the JSON messages between certower-agent and
// the server's agent API (HTTPS with mutual TLS).
//
// The agent drives the exchange. It periodically syncs to learn which
// certificates it holds and where they go, generates keys locally, sends
// CSRs when a certificate is due, installs issued versions, and reports
// the outcome. The server never connects to the agent.
package agentproto

import (
	"encoding/json"
	"time"
)

// Paths on the agent API listener.
const (
	PathEnroll   = "/agent/v1/enroll"
	PathSync     = "/agent/v1/sync"
	PathCSR      = "/agent/v1/csr"
	PathIdentity = "/agent/v1/identity"
)

// EnrollRequest redeems a one-time token. It is the only request made
// without a client certificate.
type EnrollRequest struct {
	Token    string `json:"token"`
	CSR      string `json:"csr"` // PEM; the agent's identity key stays on the host
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Version  string `json:"version"`
}

// EnrollResponse carries the agent's identity.
type EnrollResponse struct {
	AgentID     string `json:"agentId"`
	Certificate string `json:"certificate"` // PEM client certificate
	CA          string `json:"ca"`          // PEM agent CA
}

// SyncRequest reports the agent's state and asks for its assignments.
type SyncRequest struct {
	Hostname string             `json:"hostname"`
	OS       string             `json:"os"`
	Version  string             `json:"version"`
	Reports  []DeploymentReport `json:"reports,omitempty"`
}

// DeploymentReport is the outcome of installing a version on a target.
type DeploymentReport struct {
	CertificateID string `json:"certificateId"`
	VersionID     string `json:"versionId"`
	TargetID      string `json:"targetId"`
	OK            bool   `json:"ok"`
	Message       string `json:"message,omitempty"`
}

// SyncResponse lists what the agent is responsible for.
type SyncResponse struct {
	Assignments []Assignment `json:"assignments"`
	// PollSeconds is when to sync next.
	PollSeconds int `json:"pollSeconds"`
}

// Assignment is one certificate whose key lives on this agent.
type Assignment struct {
	CertificateID string   `json:"certificateId"`
	Name          string   `json:"name"`
	Names         []string `json:"names"`
	KeyType       string   `json:"keyType"`
	// Status is the certificate's status on the server.
	Status string `json:"status"`
	// RenewDue asks the agent to send a CSR for a new key.
	RenewDue bool `json:"renewDue"`
	// CSRPending means a CSR is already being processed; do not send
	// another.
	CSRPending bool     `json:"csrPending"`
	Current    *Version `json:"current,omitempty"`
	Targets    []Target `json:"targets"`
}

// Version is an issued certificate.
type Version struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"` // hex SHA-256 of the leaf
	// PublicKeySHA256 identifies the key, so the agent can find the
	// private key it generated for this version.
	PublicKeySHA256 string    `json:"publicKeySha256"`
	ChainPEM        string    `json:"chainPem"` // leaf first
	NotAfter        time.Time `json:"notAfter"`
}

// Target is where to install the certificate.
type Target struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Deployer string          `json:"deployer"`
	Settings json.RawMessage `json:"settings"`
}

// CSRRequest asks the server to issue a certificate for a key the agent
// generated.
type CSRRequest struct {
	CertificateID string `json:"certificateId"`
	CSR           string `json:"csr"` // PEM
}

// IdentityRequest renews the agent's client certificate.
type IdentityRequest struct {
	CSR string `json:"csr"` // PEM
}

// IdentityResponse carries the renewed client certificate.
type IdentityResponse struct {
	Certificate string `json:"certificate"` // PEM
}

// Error is the body of non-2xx responses.
type Error struct {
	Error string `json:"error"`
}
