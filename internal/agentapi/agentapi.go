// Package agentapi serves the API agents talk to, on its own TLS listener
// with mutual authentication. See internal/agentproto for the messages.
package agentapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tntrock/certower/internal/agentca"
	"github.com/tntrock/certower/internal/agentproto"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// EnrollPrefix marks agent enrollment tokens.
const EnrollPrefix = "cwe_"

// PollInterval is how often agents sync.
const PollInterval = 30 * time.Second

// Server handles agent requests.
type Server struct {
	Store  *store.Store
	CA     *agentca.CA
	Engine *engine.Engine
	Log    *slog.Logger
}

// Handler returns the agent API handler. Serve it with CA.ServerTLSConfig.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+agentproto.PathEnroll, s.enroll)
	mux.Handle("POST "+agentproto.PathSync, s.authed(s.sync))
	mux.Handle("POST "+agentproto.PathCSR, s.authed(s.csr))
	mux.Handle("POST "+agentproto.PathIdentity, s.authed(s.identity))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, agentproto.Error{Error: msg})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.Log.Error("agent API", "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) audit(ctx context.Context, a *store.Agent, orgID, action, objType, objID string, after any) {
	var raw json.RawMessage
	if after != nil {
		raw, _ = json.Marshal(after)
	}
	if err := s.Store.InsertAudit(ctx, store.AuditEntry{OrgID: orgID, ProjectID: a.ProjectID, ActorType: "agent", ActorID: a.ID,
		Action: action, ObjectType: objType, ObjectID: objID, After: raw}); err != nil {
		s.Log.Error("audit write failed", "err", err, "action", action)
	}
}

func (s *Server) orgOf(ctx context.Context, projectID string) string {
	p, err := s.Store.GetProject(ctx, projectID)
	if err != nil {
		return ""
	}
	return p.OrgID
}

// ---------------------------------------------------------------- enroll

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req agentproto.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	csr, err := certutil.ParseCSRPEM([]byte(req.CSR))
	if err == nil {
		// Check before redeeming, so a bad request does not burn the token.
		err = csr.CheckSignature()
	}
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	// The certificate names the agent ID, known only once the token is
	// redeemed: redeem with a placeholder fingerprint, then set the real one.
	a, err := s.Store.EnrollAgent(ctx, auth.HashToken(req.Token), "pending:"+store.NewID(), req.Hostname, req.OS, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusUnauthorized, "invalid, used or expired enrollment token")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	der, err := s.CA.SignClient(csr, a.ID)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	leaf, _ := x509.ParseCertificate(der)
	if err := s.Store.SetAgentNextCertificate(ctx, a.ID, agentca.CertFingerprint(leaf)); err != nil {
		s.internal(w, err)
		return
	}
	if err := s.Store.PromoteAgentCertificate(ctx, a.ID); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(ctx, a, s.orgOf(ctx, a.ProjectID), "agent.enroll", "agent", a.ID, map[string]string{"hostname": req.Hostname, "os": req.OS})
	s.Log.Info("agent enrolled", "agent", a.Name, "hostname", req.Hostname)
	writeJSON(w, http.StatusOK, agentproto.EnrollResponse{
		AgentID:     a.ID,
		Certificate: string(certutil.EncodeChainPEM([][]byte{der})),
		CA:          string(s.CA.CertPEM()),
	})
}

// ---------------------------------------------------------------- authentication

type handler func(w http.ResponseWriter, r *http.Request, a *store.Agent)

// authed identifies the agent by its verified client certificate.
func (s *Server) authed(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			fail(w, http.StatusUnauthorized, "a client certificate is required")
			return
		}
		ctx := r.Context()
		a, next, err := s.Store.AgentByCertificate(ctx, agentca.CertFingerprint(r.TLS.VerifiedChains[0][0]))
		if errors.Is(err, store.ErrNotFound) {
			// Deleted agents and superseded certificates end up here.
			fail(w, http.StatusUnauthorized, "unknown or revoked agent certificate")
			return
		} else if err != nil {
			s.internal(w, err)
			return
		}
		if next {
			if err := s.Store.PromoteAgentCertificate(ctx, a.ID); err != nil {
				s.internal(w, err)
				return
			}
		}
		h(w, r, a)
	})
}

// ---------------------------------------------------------------- sync

func (s *Server) sync(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req agentproto.SyncRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if err := s.Store.TouchAgent(ctx, a.ID, req.Hostname, req.OS, req.Version); err != nil {
		s.internal(w, err)
		return
	}
	certs, err := s.Store.CertificatesForAgent(ctx, a.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	byID := map[string]*store.Certificate{}
	for i := range certs {
		byID[certs[i].ID] = &certs[i]
	}

	if err := s.recordReports(ctx, a, byID, req.Reports); err != nil {
		s.internal(w, err)
		return
	}

	resp := agentproto.SyncResponse{PollSeconds: int(PollInterval.Seconds()), Assignments: []agentproto.Assignment{}}
	for _, c := range certs {
		asg, err := s.assignment(ctx, a, &c)
		if err != nil {
			s.internal(w, err)
			return
		}
		if asg != nil {
			resp.Assignments = append(resp.Assignments, *asg)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) assignment(ctx context.Context, a *store.Agent, c *store.Certificate) (*agentproto.Assignment, error) {
	if c.KeyLocation != "agent" {
		// Server-held keys are delivered by server-side connectors, which
		// are not implemented yet.
		return nil, nil
	}
	targets, err := s.Store.TargetsForCertificate(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	asg := &agentproto.Assignment{CertificateID: c.ID, Name: c.Name, Names: c.Names, KeyType: c.KeyType, Status: c.Status, Targets: []agentproto.Target{}}
	for _, t := range targets {
		if t.AgentID == a.ID {
			asg.Targets = append(asg.Targets, agentproto.Target{ID: t.ID, Name: t.Name, Deployer: t.Deployer, Settings: t.Settings})
		}
	}

	cur, err := s.Store.CurrentVersion(ctx, c.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		cur = nil
	case err != nil:
		return nil, err
	default:
		chain, err := certutil.ParseChainPEM([]byte(cur.ChainPEM))
		if err != nil {
			return nil, err
		}
		pk, err := certutil.PublicKeySHA256(chain[0].PublicKey)
		if err != nil {
			return nil, err
		}
		asg.Current = &agentproto.Version{ID: cur.ID, Fingerprint: cur.Fingerprint, PublicKeySHA256: pk, ChainPEM: cur.ChainPEM, NotAfter: cur.NotAfter}
	}

	if _, err := s.Store.OpenJob(ctx, engine.IssueDedupeKey(c.ID)); err == nil {
		asg.CSRPending = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	now := time.Now()
	asg.RenewDue = !asg.CSRPending && c.Status != store.CertInvalid &&
		(cur == nil || !cur.RenewAfter.After(now) ||
			(c.RenewRequestedAt != nil && cur.CreatedAt.Before(*c.RenewRequestedAt)))
	return asg, nil
}

func (s *Server) recordReports(ctx context.Context, a *store.Agent, certs map[string]*store.Certificate, reports []agentproto.DeploymentReport) error {
	for _, rep := range reports {
		c, ok := certs[rep.CertificateID]
		if !ok {
			continue // no longer assigned
		}
		targets, err := s.Store.TargetsForCertificate(ctx, c.ID)
		if err != nil {
			return err
		}
		mine := false
		for _, t := range targets {
			if t.ID == rep.TargetID && t.AgentID == a.ID {
				mine = true
			}
		}
		if !mine {
			continue
		}
		if _, err := s.Store.GetVersion(ctx, c.ID, rep.VersionID); errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		status, action := "done", "cert.deployed"
		if !rep.OK {
			status, action = "failed", "cert.deploy_failed"
		}
		if err := s.Store.RecordDeployment(ctx, store.Deployment{VersionID: rep.VersionID, TargetID: rep.TargetID, Status: status, Message: rep.Message}); err != nil {
			return err
		}
		s.audit(ctx, a, s.orgOf(ctx, a.ProjectID), action, "certificate", c.ID,
			map[string]string{"version": rep.VersionID, "target": rep.TargetID, "message": rep.Message})
		if !rep.OK {
			s.Engine.NotifyCertificate(ctx, c, plugin.EventDeployFailed, plugin.SeverityWarning,
				fmt.Sprintf("%s failed to deploy on %s", c.Name, a.Name), rep.Message,
				"deploy_failed:"+rep.VersionID+":"+rep.TargetID)
		}
	}
	return nil
}

// ---------------------------------------------------------------- csr

func (s *Server) csr(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req agentproto.CSRRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	c, err := s.Store.GetCertificate(ctx, req.CertificateID)
	if err == nil && c.KeyLocation != "agent" {
		err = store.ErrNotFound
	}
	if err == nil {
		err = s.assigned(ctx, a, c)
	}
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "no such certificate assigned to this agent")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	parsed, err := certutil.ParseCSRPEM([]byte(req.CSR))
	if err == nil {
		err = engine.CheckCSR(parsed, c)
	}
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	job, created, err := s.Engine.RequestIssueWithCSR(ctx, c, req.CSR)
	if err != nil {
		s.internal(w, err)
		return
	}
	if created {
		s.audit(ctx, a, s.orgOf(ctx, a.ProjectID), "cert.csr", "certificate", c.ID, map[string]string{"job": job.ID})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"jobId": job.ID, "created": created})
}

// assigned returns ErrNotFound unless one of the certificate's targets is
// on the agent.
func (s *Server) assigned(ctx context.Context, a *store.Agent, c *store.Certificate) error {
	targets, err := s.Store.TargetsForCertificate(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.AgentID == a.ID {
			return nil
		}
	}
	return store.ErrNotFound
}

// ---------------------------------------------------------------- identity

func (s *Server) identity(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req agentproto.IdentityRequest
	if !decode(w, r, &req) {
		return
	}
	csr, err := certutil.ParseCSRPEM([]byte(req.CSR))
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	der, err := s.CA.SignClient(csr, a.ID)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	leaf, _ := x509.ParseCertificate(der)
	// The old certificate keeps working until the agent uses the new one.
	if err := s.Store.SetAgentNextCertificate(r.Context(), a.ID, agentca.CertFingerprint(leaf)); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentproto.IdentityResponse{Certificate: string(certutil.EncodeChainPEM([][]byte{der}))})
}
