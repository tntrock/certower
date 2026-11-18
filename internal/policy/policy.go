// Package policy enforces the guardrails an organization puts on what a
// project may request.
package policy

import (
	"fmt"
	"strings"
	"time"
)

// KeyType is a private key algorithm and size, e.g. "ecdsa-p256", "rsa-2048".
type KeyType string

const (
	ECDSAP256 KeyType = "ecdsa-p256"
	ECDSAP384 KeyType = "ecdsa-p384"
	RSA2048   KeyType = "rsa-2048"
	RSA3072   KeyType = "rsa-3072"
	RSA4096   KeyType = "rsa-4096"
	Ed25519   KeyType = "ed25519"
)

// Policy is attached to a project. Empty lists mean "no restriction".
type Policy struct {
	// AllowedNames are name patterns:
	//   "shop.example.com"   exactly that name
	//   "*.shop.example.com" any name below shop.example.com, at any depth,
	//                        including the wildcard "*.shop.example.com"
	AllowedNames []string `json:"allowedNames"`
	// AllowedIssuers are issuer configuration IDs.
	AllowedIssuers  []string  `json:"allowedIssuers"`
	AllowedKeyTypes []KeyType `json:"allowedKeyTypes"`
	// AllowWildcard must be true for wildcard names to be requested at all.
	AllowWildcard bool `json:"allowWildcard"`
	// MaxValidity caps the requested lifetime. Zero means the CA default.
	MaxValidity time.Duration `json:"maxValidity"`
}

// Request is the part of a certificate request that policy looks at.
type Request struct {
	Names    []string
	IssuerID string
	KeyType  KeyType
	Validity time.Duration
}

// Violation explains one way a request breaks the policy.
type Violation struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

func (v Violation) String() string {
	return fmt.Sprintf("%s %q: %s", v.Field, v.Value, v.Reason)
}

// Check returns every violation of p by req. An empty result means allowed.
func (p Policy) Check(req Request) []Violation {
	var vs []Violation
	if len(req.Names) == 0 {
		vs = append(vs, Violation{Field: "names", Reason: "at least one name is required"})
	}
	for _, raw := range req.Names {
		name := normalize(raw)
		if strings.HasPrefix(name, "*.") && !p.AllowWildcard {
			vs = append(vs, Violation{Field: "names", Value: raw, Reason: "wildcard names are not allowed"})
			continue
		}
		if len(p.AllowedNames) > 0 && !p.nameAllowed(name) {
			vs = append(vs, Violation{Field: "names", Value: raw, Reason: "name is outside the allowed patterns"})
		}
	}
	if len(p.AllowedIssuers) > 0 && !contains(p.AllowedIssuers, req.IssuerID) {
		vs = append(vs, Violation{Field: "issuer", Value: req.IssuerID, Reason: "issuer is not allowed"})
	}
	if len(p.AllowedKeyTypes) > 0 && !contains(p.AllowedKeyTypes, req.KeyType) {
		vs = append(vs, Violation{Field: "keyType", Value: string(req.KeyType), Reason: "key type is not allowed"})
	}
	if p.MaxValidity > 0 && req.Validity > p.MaxValidity {
		vs = append(vs, Violation{Field: "validity", Value: req.Validity.String(), Reason: "exceeds maximum " + p.MaxValidity.String()})
	}
	return vs
}

func (p Policy) nameAllowed(name string) bool {
	for _, raw := range p.AllowedNames {
		pat := normalize(raw)
		if base, ok := strings.CutPrefix(pat, "*."); ok {
			// A wildcard pattern covers names strictly below base. The
			// requested name "*.base" is itself below base.
			if strings.HasSuffix(name, "."+base) {
				return true
			}
			continue
		}
		if name == pat {
			return true
		}
	}
	return false
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func contains[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
