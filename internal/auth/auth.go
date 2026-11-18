// Package auth hashes passwords and issues opaque bearer tokens.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Token prefixes make leaked tokens easy to recognize and route.
const (
	SessionPrefix  = "cws_" // interactive login session
	APITokenPrefix = "cwt_" // service account token
)

// NewToken returns a random token with the given prefix and its hash. Only
// the hash is stored.
func NewToken(prefix string) (token string, hash []byte) {
	b := make([]byte, 32)
	rand.Read(b)
	token = prefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token)
}

// HashToken returns the SHA-256 of a token. Tokens carry 256 bits of
// entropy, so a fast hash is sufficient.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// argon2id parameters (OWASP recommendation: m=19 MiB, t=2, p=1).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLength is enforced for local accounts.
const MinPasswordLength = 12

// HashPassword returns an argon2id hash in PHC string format.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

var errBadHash = errors.New("auth: malformed password hash")

// dummyHash is verified against when a user does not exist, so login takes
// the same time either way.
var dummyHash, _ = HashPassword("dummy-password-for-timing")

// VerifyPassword reports whether password matches hash. An empty hash
// (no local password) never matches, but still costs one hash computation.
func VerifyPassword(hash, password string) bool {
	if hash == "" {
		hash = dummyHash
		password = "\x00" + password // can never match
	}
	ok, err := verify(hash, password)
	return err == nil && ok
}

func verify(hash, password string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
