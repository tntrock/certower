package plugin

import (
	"context"
	"errors"
	"time"
)

// IdentifierType is the type of name a certificate is requested for.
type IdentifierType string

const (
	IdentifierDNS IdentifierType = "dns"
	IdentifierIP  IdentifierType = "ip"
)

// Identifier is one name on a certificate.
type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// IssueRequest asks an Issuer for a certificate.
type IssueRequest struct {
	// CSR is DER-encoded. The private key stays with whoever generated it
	// (normally the agent).
	CSR         []byte
	Identifiers []Identifier
	// Profile is a CA-specific profile name (ACME profiles, CA product code).
	Profile string
	// Replaces is the ARI certificate ID of the certificate being renewed,
	// if any (RFC 9773 "replaces" field).
	Replaces string
}

// IssuedCertificate is the result of a successful issuance.
type IssuedCertificate struct {
	// Chain holds DER certificates, leaf first.
	Chain     [][]byte
	NotBefore time.Time
	NotAfter  time.Time
	// Renewal is the CA-suggested renewal window, if the CA provides one.
	Renewal *RenewalWindow
}

// RenewalWindow is an ACME Renewal Information window.
type RenewalWindow struct {
	Start time.Time
	End   time.Time
}

// ManualActionRequired is returned by issuers that need a human step, such
// as submitting a CSR on a CA web portal. The job is parked until the
// certificate is uploaded.
type ManualActionRequired struct {
	Instructions string
}

func (e *ManualActionRequired) Error() string {
	return "manual action required: " + e.Instructions
}

// ErrNotSupported is returned for optional operations a plugin does not
// implement.
var ErrNotSupported = errors.New("operation not supported by plugin")

// ChallengeSolvers gives an Issuer access to the challenge solvers the host
// has configured for this request.
type ChallengeSolvers struct {
	// DNS solves DNS-01 challenges. Nil if no DNS provider is configured.
	DNS DNSSolver
}

// Issuer obtains certificates from a CA.
type Issuer interface {
	Plugin
	Issue(ctx context.Context, req IssueRequest, solvers ChallengeSolvers) (*IssuedCertificate, error)
	// Revoke revokes a DER-encoded certificate with an RFC 5280 reason code.
	Revoke(ctx context.Context, cert []byte, reason int) error
	// RenewalInfo returns the CA's suggested renewal window for a
	// certificate, or ErrNotSupported.
	RenewalInfo(ctx context.Context, cert []byte) (*RenewalWindow, error)
}
