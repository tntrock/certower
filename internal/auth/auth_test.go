package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(h, "wrong horse battery") {
		t.Error("wrong password accepted")
	}
	if VerifyPassword("", "anything at all") {
		t.Error("empty hash accepted a password")
	}
	if VerifyPassword("garbage", "anything at all") {
		t.Error("malformed hash accepted a password")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password accepted")
	}
}

func TestToken(t *testing.T) {
	a, ha := NewToken(SessionPrefix)
	b, _ := NewToken(SessionPrefix)
	if a == b || !strings.HasPrefix(a, SessionPrefix) {
		t.Fatalf("bad tokens %q %q", a, b)
	}
	if !bytes.Equal(ha, HashToken(a)) {
		t.Error("hash mismatch")
	}
}
