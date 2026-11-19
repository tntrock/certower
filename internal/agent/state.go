package agent

import (
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/agentproto"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/policy"
)

// The state directory holds:
//
//	agent.json            configuration
//	identity.key/.crt     client identity; ca.pem the pinned agent CA
//	keys/<sha256>.key     certificate keys, named by public key hash
//	state.json            pending keys, deployments, unsent reports

type pendingKey struct {
	PublicKeySHA256 string    `json:"publicKeySha256"`
	KeyType         string    `json:"keyType"`
	CreatedAt       time.Time `json:"createdAt"`
}

type deployState struct {
	Fingerprint string    `json:"fingerprint"`
	OK          bool      `json:"ok"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"lastAttempt"`
}

type state struct {
	// Pending maps certificate ID to the key awaiting a certificate.
	Pending map[string]pendingKey `json:"pending"`
	// Deployed maps target ID to what was last installed there.
	Deployed map[string]deployState `json:"deployed"`
	// Reports are outcomes not yet acknowledged by the server.
	Reports []agentproto.DeploymentReport `json:"reports"`
}

func loadState(dir string) (*state, error) {
	s := &state{Pending: map[string]pendingKey{}, Deployed: map[string]deployState{}}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Pending == nil {
		s.Pending = map[string]pendingKey{}
	}
	if s.Deployed == nil {
		s.Deployed = map[string]deployState{}
	}
	return s, nil
}

func (s *state) save(dir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "state.json"), b, 0o600)
}

// keyStore keeps certificate private keys, named by public key hash so an
// issued certificate finds its key.
type keyStore struct{ dir string }

func (k keyStore) path(pkHash string) string { return filepath.Join(k.dir, pkHash+".key") }

func (k keyStore) has(pkHash string) bool {
	_, err := os.Stat(k.path(pkHash))
	return err == nil
}

func (k keyStore) read(pkHash string) ([]byte, error) { return os.ReadFile(k.path(pkHash)) }

// generate creates and stores a new key, returning it and its hash.
func (k keyStore) generate(kt string) (crypto.Signer, string, error) {
	key, err := certutil.GenerateKey(policy.KeyType(kt))
	if err != nil {
		return nil, "", err
	}
	hash, err := certutil.PublicKeySHA256(key.Public())
	if err != nil {
		return nil, "", err
	}
	pemKey, err := certutil.EncodeKeyPEM(key)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		return nil, "", err
	}
	return key, hash, writeFileAtomic(k.path(hash), pemKey, 0o600)
}

func (k keyStore) load(pkHash string) (crypto.Signer, error) {
	b, err := k.read(pkHash)
	if err != nil {
		return nil, err
	}
	return certutil.ParseKeyPEM(b)
}

// prune deletes keys not in keep that are older than grace, so a key is
// never lost to a transient server-side mistake.
func (k keyStore) prune(keep map[string]bool, grace time.Duration) {
	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		hash, ok := strings.CutSuffix(e.Name(), ".key")
		if !ok || keep[hash] {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > grace {
			os.Remove(filepath.Join(k.dir, e.Name()))
		}
	}
}

// writeFileAtomic writes data to a temporary file in the same directory and
// renames it over path, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
