package policy

import (
	"testing"
	"time"
)

func TestCheckNames(t *testing.T) {
	p := Policy{
		AllowedNames:  []string{"*.shop.example.com", "shop.example.com", "api.example.com"},
		AllowWildcard: true,
	}
	tests := []struct {
		name string
		ok   bool
	}{
		{"shop.example.com", true},
		{"www.shop.example.com", true},
		{"a.b.shop.example.com", true},
		{"*.shop.example.com", true},
		{"WWW.Shop.Example.com.", true},
		{"api.example.com", true},
		{"example.com", false},
		{"*.example.com", false},
		{"evilshop.example.com", false},
		{"x.api.example.com", false},
	}
	for _, tt := range tests {
		got := len(p.Check(Request{Names: []string{tt.name}})) == 0
		if got != tt.ok {
			t.Errorf("%q allowed = %v, want %v", tt.name, got, tt.ok)
		}
	}
}

func TestWildcardRequiresOptIn(t *testing.T) {
	p := Policy{AllowedNames: []string{"*.shop.example.com"}}
	if vs := p.Check(Request{Names: []string{"*.shop.example.com"}}); len(vs) != 1 {
		t.Fatalf("want 1 violation, got %v", vs)
	}
}

func TestCheckOther(t *testing.T) {
	p := Policy{
		AllowedIssuers:  []string{"letsencrypt"},
		AllowedKeyTypes: []KeyType{ECDSAP256, RSA3072},
		MaxValidity:     100 * 24 * time.Hour,
	}
	ok := Request{Names: []string{"a.example.com"}, IssuerID: "letsencrypt", KeyType: ECDSAP256, Validity: 90 * 24 * time.Hour}
	if vs := p.Check(ok); len(vs) != 0 {
		t.Fatalf("unexpected violations: %v", vs)
	}
	bad := Request{Names: []string{"a.example.com"}, IssuerID: "other", KeyType: RSA2048, Validity: 200 * 24 * time.Hour}
	if vs := p.Check(bad); len(vs) != 3 {
		t.Fatalf("want 3 violations, got %v", vs)
	}
	if vs := p.Check(Request{}); len(vs) == 0 {
		t.Fatal("empty request should be rejected")
	}
}
