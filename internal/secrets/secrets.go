// Package secrets encrypts values at rest with envelope encryption.
//
// Each value is encrypted with its own random data key (DEK) using
// AES-256-GCM. The DEK is in turn encrypted ("wrapped") by a key-encryption
// key (KEK) that never touches the database. Both layers bind the row ID as
// additional authenticated data, so a ciphertext copied into another row
// fails to decrypt.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// KEK wraps and unwraps data keys. Implementations may be a local key file,
// HashiCorp Vault transit, or a cloud KMS.
type KEK interface {
	// ID identifies the key, so rows record which KEK wrapped them and keys
	// can be rotated.
	ID() string
	Wrap(dek, aad []byte) ([]byte, error)
	Unwrap(wrapped, aad []byte) ([]byte, error)
}

// Sealed is an encrypted value ready to store.
type Sealed struct {
	KEKID      string
	WrappedDEK []byte
	Ciphertext []byte
}

// Seal encrypts plaintext for the row identified by aad.
func Seal(kek KEK, plaintext, aad []byte) (Sealed, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Sealed{}, err
	}
	ct, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, err := kek.Wrap(dek, aad)
	if err != nil {
		return Sealed{}, fmt.Errorf("secrets: wrap data key: %w", err)
	}
	return Sealed{KEKID: kek.ID(), WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// Open decrypts a sealed value for the row identified by aad.
func Open(kek KEK, s Sealed, aad []byte) ([]byte, error) {
	if s.KEKID != kek.ID() {
		return nil, fmt.Errorf("secrets: value was sealed with key %q, but key %q is loaded", s.KEKID, kek.ID())
	}
	dek, err := kek.Unwrap(s.WrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("secrets: unwrap data key: %w", err)
	}
	return gcmOpen(dek, s.Ciphertext, aad)
}

var errDecrypt = errors.New("secrets: decryption failed")

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errDecrypt
	}
	out, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], aad)
	if err != nil {
		return nil, errDecrypt
	}
	return out, nil
}

// LocalKEK is a 256-bit AES key held in memory, loaded from a file.
type LocalKEK struct {
	key []byte
	id  string
}

// NewLocalKEK wraps a raw 32-byte key.
func NewLocalKEK(key []byte) (*LocalKEK, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets: key must be 32 bytes, got %d", len(key))
	}
	sum := sha256.Sum256(key)
	return &LocalKEK{key: append([]byte(nil), key...), id: "local:" + hex.EncodeToString(sum[:4])}, nil
}

// LoadOrCreateLocalKEK reads a hex-encoded key from path, creating the file
// with a new random key (mode 0600) if it does not exist. created reports
// whether a new key was written, so the caller can tell the operator to
// back it up.
func LoadOrCreateLocalKEK(path string) (kek *LocalKEK, created bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, false, err
		}
		// O_EXCL: never overwrite a key another process just created.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, false, err
		}
		if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
			f.Close()
			return nil, false, err
		}
		if err := f.Close(); err != nil {
			return nil, false, err
		}
		k, err := NewLocalKEK(key)
		return k, true, err
	} else if err != nil {
		return nil, false, err
	}
	key, err := hex.DecodeString(string(trimSpace(data)))
	if err != nil {
		return nil, false, fmt.Errorf("secrets: %s is not a hex key: %w", path, err)
	}
	k, err := NewLocalKEK(key)
	return k, false, err
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func (k *LocalKEK) ID() string { return k.id }

func (k *LocalKEK) Wrap(dek, aad []byte) ([]byte, error) {
	return gcmSeal(k.key, dek, append([]byte("dek:"), aad...))
}

func (k *LocalKEK) Unwrap(wrapped, aad []byte) ([]byte, error) {
	return gcmOpen(k.key, wrapped, append([]byte("dek:"), aad...))
}
