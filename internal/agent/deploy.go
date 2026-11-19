package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/certutil"
)

// Settings configure the built-in deployers. Every path must be inside the
// agent's allowedPaths and every command one of its allowedCommands.
type Settings struct {
	CertPath      string `json:"certPath,omitempty"`      // leaf only
	ChainPath     string `json:"chainPath,omitempty"`     // intermediates only
	FullchainPath string `json:"fullchainPath,omitempty"` // leaf and intermediates
	KeyPath       string `json:"keyPath"`
	// TestCommand checks the service configuration before reloading.
	TestCommand []string `json:"testCommand,omitempty"`
	// ReloadCommand makes the service pick up the new files.
	ReloadCommand []string `json:"reloadCommand,omitempty"`
	// VerifyEndpoint (host:port) is connected to after reloading to check
	// the new certificate is served. VerifyServerName sets the SNI.
	VerifyEndpoint   string `json:"verifyEndpoint,omitempty"`
	VerifyServerName string `json:"verifyServerName,omitempty"`
}

// Deployers lists the built-in deployers.
var Deployers = []string{"files", "nginx"}

// ResolveSettings applies a deployer's defaults and validates the result.
func ResolveSettings(deployer string, raw json.RawMessage) (*Settings, error) {
	var s Settings
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
	}
	switch deployer {
	case "files":
		if s.CertPath == "" && s.FullchainPath == "" {
			return nil, errors.New("files deployer needs certPath or fullchainPath")
		}
	case "nginx":
		if s.FullchainPath == "" {
			return nil, errors.New("nginx deployer needs fullchainPath (used as ssl_certificate)")
		}
		if s.TestCommand == nil {
			s.TestCommand = []string{"nginx", "-t"}
		}
		if s.ReloadCommand == nil {
			s.ReloadCommand = []string{"nginx", "-s", "reload"}
		}
		if s.VerifyEndpoint == "" {
			s.VerifyEndpoint = "127.0.0.1:443"
		}
	default:
		return nil, fmt.Errorf("unknown deployer %q (have %v)", deployer, Deployers)
	}
	if s.KeyPath == "" {
		return nil, errors.New("keyPath is required")
	}
	if s.VerifyEndpoint != "" {
		if _, _, err := net.SplitHostPort(s.VerifyEndpoint); err != nil {
			return nil, fmt.Errorf("verifyEndpoint: %w", err)
		}
	}
	return &s, nil
}

// bundle is what gets installed.
type bundle struct {
	chain       [][]byte // DER, leaf first
	keyPEM      []byte
	fingerprint string
	names       []string
}

// fileSnapshot remembers a file's previous content for rollback.
type fileSnapshot struct {
	path    string
	existed bool
	data    []byte
	mode    os.FileMode
}

// deploy installs b according to s. On any failure after files were
// written it restores the previous files and, if a reload had run, reloads
// again, so the service keeps serving the old certificate.
func (a *Agent) deploy(ctx context.Context, s *Settings, b bundle) (string, error) {
	files := map[string][]byte{}
	if s.CertPath != "" {
		files[s.CertPath] = certutil.EncodeChainPEM(b.chain[:1])
	}
	if s.ChainPath != "" {
		files[s.ChainPath] = certutil.EncodeChainPEM(b.chain[1:])
	}
	if s.FullchainPath != "" {
		files[s.FullchainPath] = certutil.EncodeChainPEM(b.chain)
	}
	files[s.KeyPath] = b.keyPEM

	for path := range files {
		if err := a.cfg.pathAllowed(path); err != nil {
			return "", err
		}
	}
	for _, cmd := range [][]string{s.TestCommand, s.ReloadCommand} {
		if len(cmd) > 0 && !a.cfg.commandAllowed(cmd) {
			return "", fmt.Errorf("command %q is not in allowedCommands (edit agent.json on the host to allow it)", strings.Join(cmd, " "))
		}
	}

	var snaps []fileSnapshot
	for path := range files {
		snap := fileSnapshot{path: path}
		if info, err := os.Stat(path); err == nil {
			snap.existed, snap.mode = true, info.Mode().Perm()
			if snap.data, err = os.ReadFile(path); err != nil {
				return "", err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		snaps = append(snaps, snap)
	}
	reloaded := false
	rollback := func(cause error) (string, error) {
		for _, sn := range snaps {
			if sn.existed {
				writeFileAtomic(sn.path, sn.data, sn.mode)
			} else {
				os.Remove(sn.path)
			}
		}
		if reloaded {
			a.run(ctx, s.ReloadCommand)
		}
		return "", fmt.Errorf("%w; previous files restored", cause)
	}

	for path, data := range files {
		mode := os.FileMode(0o644)
		if path == s.KeyPath {
			mode = 0o600
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return rollback(err)
		}
		if err := writeFileAtomic(path, data, mode); err != nil {
			return rollback(err)
		}
	}
	if len(s.TestCommand) > 0 {
		if out, err := a.run(ctx, s.TestCommand); err != nil {
			return rollback(fmt.Errorf("%s failed: %v: %s", strings.Join(s.TestCommand, " "), err, out))
		}
	}
	if len(s.ReloadCommand) > 0 {
		reloaded = true
		if out, err := a.run(ctx, s.ReloadCommand); err != nil {
			return rollback(fmt.Errorf("%s failed: %v: %s", strings.Join(s.ReloadCommand, " "), err, out))
		}
	}
	if s.VerifyEndpoint == "" {
		return "installed (not verified: no verifyEndpoint)", nil
	}
	if err := a.verify(ctx, s, b); err != nil {
		return rollback(err)
	}
	return "installed and verified at " + s.VerifyEndpoint, nil
}

// run executes an allowed command with a timeout and returns its output.
func (a *Agent) run(ctx context.Context, cmd []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return s, err
}

// verify connects to the endpoint until it serves the new certificate.
// Services reload asynchronously, so it retries for a while.
func (a *Agent) verify(ctx context.Context, s *Settings, b bundle) error {
	sni := s.VerifyServerName
	if sni == "" {
		sni = strings.Replace(b.names[0], "*", "certower-verify", 1)
	}
	deadline := time.Now().Add(a.VerifyTimeout)
	var last string
	for {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", s.VerifyEndpoint, &tls.Config{
			ServerName: sni,
			// Only the fingerprint matters here; the chain was checked
			// when the certificate was issued.
			InsecureSkipVerify: true,
		})
		if err == nil {
			got := certutil.Fingerprint(conn.ConnectionState().PeerCertificates[0].Raw)
			conn.Close()
			if got == b.fingerprint {
				return nil
			}
			last = "serves certificate " + got[:16] + "…, expected " + b.fingerprint[:16] + "…"
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("verification at %s failed: %s", s.VerifyEndpoint, last)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
