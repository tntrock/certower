package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tntrock/certower/internal/agentproto"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/version"
)

// keyGrace is how long a key no longer referenced by the server is kept.
const keyGrace = 30 * 24 * time.Hour

// pendingMaxAge is when a key still waiting for a certificate is replaced.
const pendingMaxAge = 7 * 24 * time.Hour

// Agent is a running, enrolled agent.
type Agent struct {
	dir  string
	cfg  *Config
	log  *slog.Logger
	http *http.Client

	mu       sync.Mutex
	identity *tls.Certificate

	st   *state
	keys keyStore

	// VerifyTimeout bounds deployment verification. Default 15s.
	VerifyTimeout time.Duration
}

// EnrollOptions configure enrollment.
type EnrollOptions struct {
	Server   string // https://host:port of the agent API
	Token    string
	CASHA256 string
	StateDir string
	// AllowedPaths and AllowedCommands default to DefaultAllowedPaths and
	// DefaultAllowedCommands.
	AllowedPaths    []string
	AllowedCommands [][]string
}

// Enroll redeems a token and stores the agent's identity.
func Enroll(ctx context.Context, o EnrollOptions) (*Config, error) {
	if o.Server == "" || o.Token == "" || o.CASHA256 == "" {
		return nil, errors.New("server, token and CA fingerprint are required")
	}
	if _, err := os.Stat(configPath(o.StateDir)); err == nil {
		return nil, fmt.Errorf("already enrolled: %s exists", configPath(o.StateDir))
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return nil, err
	}
	key, err := certutil.GenerateKey(policy.ECDSAP256)
	if err != nil {
		return nil, err
	}
	csr, err := certutil.CreateCSR(key, []string{"certower-agent"})
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: agentproto.PinnedClientConfig(o.CASHA256)}}
	var resp agentproto.EnrollResponse
	err = post(ctx, client, strings.TrimSuffix(o.Server, "/")+agentproto.PathEnroll, agentproto.EnrollRequest{
		Token: o.Token, CSR: string(certutil.EncodeCSRPEM(csr)), Hostname: hostname, OS: runtime.GOOS + "/" + runtime.GOARCH, Version: version.Version,
	}, &resp)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	// The returned CA must be the one we pinned.
	ca, err := certutil.ParseChainPEM([]byte(resp.CA))
	if err != nil || certutil.Fingerprint(ca[0].Raw) != strings.ToLower(strings.ReplaceAll(o.CASHA256, ":", "")) {
		return nil, errors.New("enroll: server returned a CA that does not match the pinned fingerprint")
	}

	keyPEM, err := certutil.EncodeKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(o.StateDir, "identity.key"), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(o.StateDir, "identity.crt"), []byte(resp.Certificate), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(o.StateDir, "ca.pem"), []byte(resp.CA), 0o600); err != nil {
		return nil, err
	}
	cfg := &Config{Server: strings.TrimSuffix(o.Server, "/"), AgentID: resp.AgentID, CASHA256: certutil.Fingerprint(ca[0].Raw),
		AllowedPaths: o.AllowedPaths, AllowedCommands: o.AllowedCommands}
	if cfg.AllowedPaths == nil {
		cfg.AllowedPaths = DefaultAllowedPaths()
	}
	if cfg.AllowedCommands == nil {
		cfg.AllowedCommands = DefaultAllowedCommands()
	}
	return cfg, cfg.save(o.StateDir)
}

// Open loads an enrolled agent from its state directory.
func Open(stateDir string, log *slog.Logger) (*Agent, error) {
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	a := &Agent{dir: stateDir, cfg: cfg, log: log, keys: keyStore{dir: filepath.Join(stateDir, "keys")}, VerifyTimeout: 15 * time.Second}
	if err := a.recoverIdentity(); err != nil {
		return nil, err
	}
	if err := a.loadIdentity(); err != nil {
		return nil, err
	}
	if a.st, err = loadState(stateDir); err != nil {
		return nil, err
	}
	tlsCfg := agentproto.PinnedClientConfig(cfg.CASHA256)
	tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.identity, nil
	}
	a.http = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsCfg}}
	return a, nil
}

func (a *Agent) loadIdentity() error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(a.dir, "identity.crt"), filepath.Join(a.dir, "identity.key"))
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if cert.Leaf == nil {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	a.mu.Lock()
	a.identity = &cert
	a.mu.Unlock()
	return nil
}

// recoverIdentity finishes an identity renewal interrupted between writing
// the new key and certificate and putting them in place.
func (a *Agent) recoverIdentity() error {
	nextKey, nextCrt := filepath.Join(a.dir, "identity.next.key"), filepath.Join(a.dir, "identity.next.crt")
	_, errK := os.Stat(nextKey)
	_, errC := os.Stat(nextCrt)
	switch {
	case errK == nil && errC == nil:
		if err := os.Rename(nextKey, filepath.Join(a.dir, "identity.key")); err != nil {
			return err
		}
		return os.Rename(nextCrt, filepath.Join(a.dir, "identity.crt"))
	case errK == nil:
		return os.Remove(nextKey) // the server never answered; keep the old identity
	}
	return nil
}

// Run syncs until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent started", "agent", a.cfg.AgentID, "server", a.cfg.Server)
	for {
		wait, err := a.SyncOnce(ctx)
		if err != nil {
			a.log.Error("sync failed", "err", err)
			wait = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// SyncOnce does one round: renew the identity if needed, report, fetch
// assignments, and act on them. It returns when to sync next.
func (a *Agent) SyncOnce(ctx context.Context) (time.Duration, error) {
	if err := a.maybeRenewIdentity(ctx); err != nil {
		a.log.Warn("identity renewal failed; will retry", "err", err)
	}
	hostname, _ := os.Hostname()
	var resp agentproto.SyncResponse
	err := post(ctx, a.http, a.cfg.Server+agentproto.PathSync, agentproto.SyncRequest{
		Hostname: hostname, OS: runtime.GOOS + "/" + runtime.GOARCH, Version: version.Version, Reports: a.st.Reports,
	}, &resp)
	if err != nil {
		return 0, err
	}
	a.st.Reports = nil

	keep := map[string]bool{}
	for _, asg := range resp.Assignments {
		if err := a.reconcile(ctx, asg); err != nil {
			a.log.Error("certificate", "name", asg.Name, "err", err)
		}
		if asg.Current != nil {
			keep[asg.Current.PublicKeySHA256] = true
		}
		if p, ok := a.st.Pending[asg.CertificateID]; ok {
			keep[p.PublicKeySHA256] = true
		}
	}
	a.keys.prune(keep, keyGrace)
	if err := a.st.save(a.dir); err != nil {
		return 0, err
	}
	wait := time.Duration(resp.PollSeconds) * time.Second
	if wait <= 0 {
		wait = 30 * time.Second
	}
	if len(a.st.Reports) > 0 {
		wait = time.Second // report outcomes promptly
	}
	return wait, nil
}

func (a *Agent) reconcile(ctx context.Context, asg agentproto.Assignment) error {
	cur := asg.Current
	haveKey := cur != nil && a.keys.has(cur.PublicKeySHA256)

	if p, ok := a.st.Pending[asg.CertificateID]; ok && cur != nil && cur.PublicKeySHA256 == p.PublicKeySHA256 {
		delete(a.st.Pending, asg.CertificateID) // the pending key got its certificate
	}

	if haveKey {
		for _, t := range asg.Targets {
			a.maybeDeploy(ctx, asg, t)
		}
	}

	// A lost key (say, the host was rebuilt) needs a new certificate too,
	// unless the server has given up on this certificate.
	needCSR := asg.RenewDue || (cur != nil && !haveKey && asg.Status != "invalid")
	if !needCSR || asg.CSRPending {
		return nil
	}
	p, ok := a.st.Pending[asg.CertificateID]
	if !ok || p.KeyType != asg.KeyType || time.Since(p.CreatedAt) > pendingMaxAge || !a.keys.has(p.PublicKeySHA256) {
		_, hash, err := a.keys.generate(asg.KeyType)
		if err != nil {
			return err
		}
		p = pendingKey{PublicKeySHA256: hash, KeyType: asg.KeyType, CreatedAt: time.Now()}
		a.st.Pending[asg.CertificateID] = p
		if err := a.st.save(a.dir); err != nil {
			return err
		}
	}
	key, err := a.keys.load(p.PublicKeySHA256)
	if err != nil {
		return err
	}
	csr, err := certutil.CreateCSR(key, asg.Names)
	if err != nil {
		return err
	}
	a.log.Info("requesting certificate", "name", asg.Name)
	return post(ctx, a.http, a.cfg.Server+agentproto.PathCSR,
		agentproto.CSRRequest{CertificateID: asg.CertificateID, CSR: string(certutil.EncodeCSRPEM(csr))}, nil)
}

// retryDelay is how long to wait after the n-th failed deployment.
func retryDelay(attempts int) time.Duration {
	d := time.Hour
	if attempts < 7 {
		d = min(time.Duration(1<<attempts)*time.Minute, d)
	}
	return d
}

func (a *Agent) maybeDeploy(ctx context.Context, asg agentproto.Assignment, t agentproto.Target) {
	cur := asg.Current
	prev := a.st.Deployed[t.ID]
	if prev.Fingerprint == cur.Fingerprint {
		if prev.OK || time.Since(prev.LastAttempt) < retryDelay(prev.Attempts) {
			return
		}
	} else {
		prev = deployState{Fingerprint: cur.Fingerprint}
	}

	report := agentproto.DeploymentReport{CertificateID: asg.CertificateID, VersionID: cur.ID, TargetID: t.ID}
	msg, err := a.deployVersion(ctx, asg, t)
	prev.Attempts++
	prev.LastAttempt = time.Now()
	prev.OK = err == nil
	if err != nil {
		report.Message = err.Error()
		a.log.Error("deployment failed", "certificate", asg.Name, "target", t.Name, "err", err)
	} else {
		report.OK, report.Message = true, msg
		a.log.Info("deployed", "certificate", asg.Name, "target", t.Name, "result", msg)
	}
	a.st.Deployed[t.ID] = prev
	a.st.Reports = append(a.st.Reports, report)
}

func (a *Agent) deployVersion(ctx context.Context, asg agentproto.Assignment, t agentproto.Target) (string, error) {
	s, err := ResolveSettings(t.Deployer, t.Settings)
	if err != nil {
		return "", err
	}
	chain, err := certutil.ParseChainPEM([]byte(asg.Current.ChainPEM))
	if err != nil {
		return "", err
	}
	// Never trust the server's word on which key fits: check.
	pk, err := certutil.PublicKeySHA256(chain[0].PublicKey)
	if err != nil || pk != asg.Current.PublicKeySHA256 || certutil.Fingerprint(chain[0].Raw) != asg.Current.Fingerprint {
		return "", errors.New("certificate does not match the advertised key or fingerprint")
	}
	keyPEM, err := a.keys.read(pk)
	if err != nil {
		return "", err
	}
	b := bundle{keyPEM: keyPEM, fingerprint: asg.Current.Fingerprint, names: asg.Names}
	for _, c := range chain {
		b.chain = append(b.chain, c.Raw)
	}
	return a.deploy(ctx, s, b)
}

// maybeRenewIdentity renews the client certificate when a third of its
// lifetime remains.
func (a *Agent) maybeRenewIdentity(ctx context.Context) error {
	a.mu.Lock()
	leaf := a.identity.Leaf
	a.mu.Unlock()
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	if time.Until(leaf.NotAfter) > life/3 {
		return nil
	}
	key, err := certutil.GenerateKey(policy.ECDSAP256)
	if err != nil {
		return err
	}
	keyPEM, err := certutil.EncodeKeyPEM(key)
	if err != nil {
		return err
	}
	csr, err := certutil.CreateCSR(key, []string{"certower-agent"})
	if err != nil {
		return err
	}
	nextKey, nextCrt := filepath.Join(a.dir, "identity.next.key"), filepath.Join(a.dir, "identity.next.crt")
	if err := writeFileAtomic(nextKey, keyPEM, 0o600); err != nil {
		return err
	}
	var resp agentproto.IdentityResponse
	if err := post(ctx, a.http, a.cfg.Server+agentproto.PathIdentity, agentproto.IdentityRequest{CSR: string(certutil.EncodeCSRPEM(csr))}, &resp); err != nil {
		os.Remove(nextKey)
		return err
	}
	if err := writeFileAtomic(nextCrt, []byte(resp.Certificate), 0o600); err != nil {
		return err
	}
	if err := a.recoverIdentity(); err != nil { // moves next into place
		return err
	}
	if err := a.loadIdentity(); err != nil {
		return err
	}
	// New connections present the new certificate; the server retires the
	// old one when it first sees the new one.
	a.http.Transport.(*http.Transport).CloseIdleConnections()
	a.log.Info("agent identity renewed")
	return nil
}

// post sends a JSON request and decodes a JSON response into out (if not
// nil). Non-2xx responses become errors carrying the server's message.
func post(ctx context.Context, c *http.Client, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode/100 != 2 {
		var e agentproto.Error
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("server: %s (%d)", e.Error, resp.StatusCode)
		}
		return fmt.Errorf("server: %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
