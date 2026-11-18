package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpen(t *testing.T) {
	kek, err := NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Seal(kek, []byte("cloudflare-token"), []byte("row-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, []byte("cloudflare-token")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := Open(kek, s, []byte("row-1"))
	if err != nil || string(got) != "cloudflare-token" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := Open(kek, s, []byte("row-2")); err == nil {
		t.Fatal("ciphertext moved to another row still decrypts")
	}
	other, _ := NewLocalKEK(bytes.Repeat([]byte{8}, 32))
	if _, err := Open(other, s, []byte("row-1")); err == nil {
		t.Fatal("wrong KEK decrypts")
	}
	s.Ciphertext[len(s.Ciphertext)-1] ^= 1
	if _, err := Open(kek, s, []byte("row-1")); err == nil {
		t.Fatal("tampered ciphertext decrypts")
	}
}

func TestLoadOrCreateLocalKEK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certower.kek")
	a, created, err := LoadOrCreateLocalKEK(path)
	if err != nil || !created {
		t.Fatalf("create: %v, created=%v", err, created)
	}
	b, created, err := LoadOrCreateLocalKEK(path)
	if err != nil || created || a.ID() != b.ID() {
		t.Fatalf("reload: %v, created=%v, ids %s %s", err, created, a.ID(), b.ID())
	}
	os.WriteFile(path, []byte("not hex"), 0o600)
	if _, _, err := LoadOrCreateLocalKEK(path); err == nil {
		t.Fatal("corrupt key file accepted")
	}
}
