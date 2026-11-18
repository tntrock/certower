// Package engine runs background work: issuing and renewing certificates on
// schedule, refreshing ACME renewal windows, and retrying failures.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// Job types.
const JobIssue = "issue"

// Engine runs jobs and schedules renewals.
type Engine struct {
	Store   *store.Store
	Vault   *secrets.Vault
	Configs *pluginconfig.Service
	Log     *slog.Logger

	// Workers is how many jobs run at once. Default 4.
	Workers int
	// Lease is how long a worker may hold a job before another may take it
	// over. Default 10 minutes.
	Lease time.Duration
	// Poll is how often idle workers look for jobs. Default 5 seconds.
	Poll time.Duration
	// ScheduleEvery is how often renewals are scheduled. Default 5 minutes.
	ScheduleEvery time.Duration
	// ARIEvery is how often a certificate's renewal window is re-checked.
	// Default 6 hours.
	ARIEvery time.Duration

	// Now is the clock, replaceable in tests.
	Now func() time.Time

	workerID string
	wake     chan struct{}
	initOnce sync.Once
}

func (e *Engine) init() {
	e.initOnce.Do(func() {
		if e.Workers <= 0 {
			e.Workers = 4
		}
		if e.Lease <= 0 {
			e.Lease = 10 * time.Minute
		}
		if e.Poll <= 0 {
			e.Poll = 5 * time.Second
		}
		if e.ScheduleEvery <= 0 {
			e.ScheduleEvery = 5 * time.Minute
		}
		if e.ARIEvery <= 0 {
			e.ARIEvery = 6 * time.Hour
		}
		if e.Now == nil {
			e.Now = time.Now
		}
		if e.Log == nil {
			e.Log = slog.Default()
		}
		host, _ := os.Hostname()
		b := make([]byte, 4)
		rand.Read(b)
		e.workerID = host + "-" + hex.EncodeToString(b)
		e.wake = make(chan struct{}, 1)
	})
}

// Run starts the workers and the scheduler and blocks until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	e.init()
	var wg sync.WaitGroup
	for i := 0; i < e.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.workLoop(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.scheduleLoop(ctx)
	}()
	wg.Wait()
}

func (e *Engine) workLoop(ctx context.Context) {
	t := time.NewTicker(e.Poll)
	defer t.Stop()
	for {
		// Drain all runnable jobs before sleeping.
		for {
			ran, err := e.RunOne(ctx)
			if err != nil && ctx.Err() == nil {
				e.Log.Error("job queue", "err", err)
			}
			if !ran || ctx.Err() != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.wake:
		}
	}
}

func (e *Engine) scheduleLoop(ctx context.Context) {
	t := time.NewTicker(e.ScheduleEvery)
	defer t.Stop()
	for {
		if err := e.Schedule(ctx); err != nil && ctx.Err() == nil {
			e.Log.Error("schedule renewals", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// notify wakes an idle worker.
func (e *Engine) notify() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

type issuePayload struct {
	CertificateID string `json:"certificateId"`
}

// RequestIssue queues issuance (or renewal) of a certificate. At most one
// such job per certificate is open at a time; a second request returns the
// open job.
func (e *Engine) RequestIssue(ctx context.Context, cert *store.Certificate) (*store.Job, error) {
	e.init()
	payload, _ := json.Marshal(issuePayload{CertificateID: cert.ID})
	j, _, err := e.Store.EnqueueJob(ctx, store.Job{
		ProjectID: cert.ProjectID, Type: JobIssue, Payload: payload, DedupeKey: "issue:" + cert.ID,
	})
	if err == nil {
		e.notify()
	}
	return j, err
}

// RunOne claims and runs one job. It reports whether a job was run.
func (e *Engine) RunOne(ctx context.Context) (bool, error) {
	e.init()
	j, err := e.Store.ClaimJob(ctx, e.workerID, e.Lease)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	var jobErr error
	switch j.Type {
	case JobIssue:
		jobErr = e.runIssue(ctx, j)
	default:
		jobErr = permanent(fmt.Errorf("unknown job type %q", j.Type))
	}

	switch {
	case jobErr == nil:
		return true, e.Store.CompleteJob(ctx, j.ID)
	case isPermanent(jobErr):
		e.Log.Warn("job failed", "job", j.ID, "type", j.Type, "err", jobErr)
		return true, e.Store.FailJob(ctx, j.ID, jobErr.Error())
	default:
		next := e.Now().Add(Backoff(j.Attempts))
		e.Log.Warn("job will be retried", "job", j.ID, "type", j.Type, "attempt", j.Attempts, "retryAt", next, "err", jobErr)
		return true, e.Store.RetryJob(ctx, j.ID, next, jobErr.Error())
	}
}

// Backoff is the delay before retry number attempt (1-based): 1, 2, 4 ...
// minutes, capped at 6 hours, with up to 20% jitter.
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := 6 * time.Hour
	if attempt <= 9 { // 2^9 minutes > 6h
		d = min(time.Duration(1<<(attempt-1))*time.Minute, d)
	}
	return d + randDuration(d/5)
}

func randDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// permanentError marks failures that retrying cannot fix.
type permanentError struct{ error }

func (p permanentError) Unwrap() error { return p.error }

func permanent(err error) error { return permanentError{err} }

func isPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// runIssue issues a new version of a certificate.
func (e *Engine) runIssue(ctx context.Context, j *store.Job) (err error) {
	var p issuePayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return permanent(err)
	}
	cert, err := e.Store.GetCertificate(ctx, p.CertificateID)
	if errors.Is(err, store.ErrNotFound) {
		return permanent(errors.New("certificate was deleted"))
	} else if err != nil {
		return err
	}

	// Record the outcome on the certificate for the UI.
	defer func() {
		switch {
		case err == nil:
			err = e.Store.SetCertificateStatus(ctx, cert.ID, store.CertActive, "")
		case isPermanent(err):
			e.Store.SetCertificateStatus(ctx, cert.ID, store.CertInvalid, err.Error())
		default:
			e.Store.SetCertificateStatus(ctx, cert.ID, store.CertFailing, err.Error())
		}
	}()

	project, err := e.Store.GetProject(ctx, cert.ProjectID)
	if err != nil {
		return err
	}
	issuerCfg, err := e.Store.GetPluginConfig(ctx, cert.IssuerConfigID)
	if err != nil {
		return err
	}

	// Policy can change after a certificate was created, so check again.
	pol, err := e.Store.GetPolicy(ctx, project.ID)
	if err != nil {
		return err
	}
	if vs := pol.Check(policy.Request{Names: cert.Names, IssuerID: issuerCfg.Name, KeyType: policy.KeyType(cert.KeyType)}); len(vs) > 0 {
		return permanent(fmt.Errorf("policy violation: %s", joinViolations(vs)))
	}

	ip, err := e.Configs.Instantiate(ctx, issuerCfg)
	if err != nil {
		return permanent(err)
	}
	issuer, ok := ip.(plugin.Issuer)
	if !ok {
		return permanent(fmt.Errorf("config %q is not an issuer", issuerCfg.Name))
	}
	var solvers plugin.ChallengeSolvers
	if cert.DNSConfigID != "" {
		dnsCfg, err := e.Store.GetPluginConfig(ctx, cert.DNSConfigID)
		if err != nil {
			return err
		}
		dp, err := e.Configs.Instantiate(ctx, dnsCfg)
		if err != nil {
			return permanent(err)
		}
		if solvers.DNS, ok = dp.(plugin.DNSSolver); !ok {
			return permanent(fmt.Errorf("config %q is not a DNS provider", dnsCfg.Name))
		}
	}

	if cert.KeyLocation != "server" {
		return permanent(fmt.Errorf("key location %q is not supported yet", cert.KeyLocation))
	}
	key, err := certutil.GenerateKey(policy.KeyType(cert.KeyType))
	if err != nil {
		return permanent(err)
	}
	csr, err := certutil.CreateCSR(key, cert.Names)
	if err != nil {
		return permanent(err)
	}

	req := plugin.IssueRequest{CSR: csr, Profile: cert.Profile}
	if cur, err := e.Store.CurrentVersion(ctx, cert.ID); err == nil {
		req.Replaces = cur.ARICertID
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	issued, err := issuer.Issue(ctx, req, solvers)
	if err != nil {
		var manual *plugin.ManualActionRequired
		if errors.As(err, &manual) || errors.Is(err, plugin.ErrRejected) {
			// Waits for a person; manual issuance arrives with the manual issuer.
			return permanent(err)
		}
		return err
	}
	if len(issued.Chain) == 0 {
		return errors.New("issuer returned an empty chain")
	}
	leaf, err := x509.ParseCertificate(issued.Chain[0])
	if err != nil {
		return fmt.Errorf("issuer returned an unparsable certificate: %w", err)
	}
	keyPEM, err := certutil.EncodeKeyPEM(key)
	if err != nil {
		return err
	}

	versionID := store.NewID()
	ariID, _ := certutil.ARICertID(leaf) // empty when the CA sets no AKI
	err = e.Store.InTx(ctx, func(tx *store.Store) error {
		keyID, err := e.Vault.WithStore(tx).Put(ctx, project.OrgID, project.ID, "certkey:"+versionID, keyPEM)
		if err != nil {
			return err
		}
		_, err = tx.InsertCertificateVersion(ctx, store.CertificateVersion{
			ID: versionID, CertificateID: cert.ID,
			Serial: leaf.SerialNumber.Text(16), Fingerprint: certutil.Fingerprint(leaf.Raw), ARICertID: ariID,
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			RenewAfter: RenewAt(leaf.NotBefore, leaf.NotAfter, issued.Renewal, cert.RenewBeforeRatio),
			ChainPEM:   string(certutil.EncodeChainPEM(issued.Chain)), KeySecretID: keyID,
		})
		if err != nil {
			return err
		}
		after, _ := json.Marshal(map[string]any{"version": versionID, "serial": leaf.SerialNumber.Text(16), "notAfter": leaf.NotAfter})
		return tx.InsertAudit(ctx, store.AuditEntry{
			OrgID: project.OrgID, ProjectID: project.ID, ActorType: "system", ActorID: "engine",
			Action: "cert.issued", ObjectType: "certificate", ObjectID: cert.ID, After: after,
		})
	})
	if err != nil {
		return err
	}
	e.Log.Info("certificate issued", "certificate", cert.Name, "project", project.Slug, "notAfter", leaf.NotAfter)
	return nil
}

func joinViolations(vs []policy.Violation) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = v.String()
	}
	return strings.Join(parts, "; ")
}

// RenewAt picks when to renew. With an ARI window it is a uniformly random
// time inside the window, as RFC 9773 asks, so renewals spread out.
// Otherwise it is when renewBefore (a fraction) of the lifetime remains.
func RenewAt(notBefore, notAfter time.Time, w *plugin.RenewalWindow, renewBefore float64) time.Time {
	if w != nil && w.End.After(w.Start) {
		return w.Start.Add(randDuration(w.End.Sub(w.Start)))
	}
	if renewBefore <= 0 || renewBefore >= 1 {
		renewBefore = 1.0 / 3
	}
	life := notAfter.Sub(notBefore)
	return notAfter.Add(-time.Duration(float64(life) * renewBefore))
}

// Schedule queues issuance for certificates that are due and refreshes
// renewal windows from ARI. Run calls it periodically.
func (e *Engine) Schedule(ctx context.Context) error {
	e.init()
	due, err := e.Store.CertificatesDue(ctx, e.Now(), 500)
	if err != nil {
		return err
	}
	for _, id := range due {
		cert, err := e.Store.GetCertificate(ctx, id)
		if err != nil {
			continue
		}
		if _, err := e.RequestIssue(ctx, cert); err != nil {
			return err
		}
	}
	return e.refreshARI(ctx)
}

// refreshARI re-asks CAs for renewal windows. A CA moves a window earlier,
// for example, ahead of a mass revocation.
func (e *Engine) refreshARI(ctx context.Context) error {
	versions, err := e.Store.VersionsForARICheck(ctx, e.Now().Add(-e.ARIEvery), 100)
	if err != nil {
		return err
	}
	for _, v := range versions {
		newAt := v.RenewAfter
		w, err := e.renewalWindow(ctx, &v)
		switch {
		case errors.Is(err, plugin.ErrNotSupported):
		case err != nil:
			e.Log.Warn("ARI check failed", "version", v.ID, "err", err)
			continue // try again next round
		case newAt.Before(w.Start) || !newAt.Before(w.End):
			newAt = RenewAt(v.NotBefore, v.NotAfter, w, 0)
			e.Log.Info("CA moved renewal window", "version", v.ID, "renewAt", newAt)
		}
		if err := e.Store.UpdateVersionRenewal(ctx, v.ID, newAt); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) renewalWindow(ctx context.Context, v *store.CertificateVersion) (*plugin.RenewalWindow, error) {
	cert, err := e.Store.GetCertificate(ctx, v.CertificateID)
	if err != nil {
		return nil, err
	}
	issuer, err := e.issuer(ctx, cert)
	if err != nil {
		return nil, err
	}
	leaf, err := leafDER(v.ChainPEM)
	if err != nil {
		return nil, err
	}
	return issuer.RenewalInfo(ctx, leaf)
}

func (e *Engine) issuer(ctx context.Context, cert *store.Certificate) (plugin.Issuer, error) {
	pc, err := e.Store.GetPluginConfig(ctx, cert.IssuerConfigID)
	if err != nil {
		return nil, err
	}
	p, err := e.Configs.Instantiate(ctx, pc)
	if err != nil {
		return nil, err
	}
	issuer, ok := p.(plugin.Issuer)
	if !ok {
		return nil, fmt.Errorf("config %q is not an issuer", pc.Name)
	}
	return issuer, nil
}

// Revoke revokes a version with the CA and records it. The scheduler then
// issues a replacement, since the certificate no longer has a valid version.
func (e *Engine) Revoke(ctx context.Context, cert *store.Certificate, v *store.CertificateVersion, reason int) error {
	e.init()
	if v.RevokedAt != nil {
		return errors.New("version is already revoked")
	}
	issuer, err := e.issuer(ctx, cert)
	if err != nil {
		return err
	}
	leaf, err := leafDER(v.ChainPEM)
	if err != nil {
		return err
	}
	if err := issuer.Revoke(ctx, leaf, reason); err != nil {
		return err
	}
	return e.Store.MarkVersionRevoked(ctx, v.ID, reason)
}

func leafDER(chainPEM string) ([]byte, error) {
	chain, err := certutil.ParseChainPEM([]byte(chainPEM))
	if err != nil {
		return nil, err
	}
	return chain[0].Raw, nil
}
