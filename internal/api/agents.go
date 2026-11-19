package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tntrock/certower/internal/agent"
	"github.com/tntrock/certower/internal/agentapi"
	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/store"
)

// ---------------------------------------------------------------- agents

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		return
	}
	agents, err := s.store.ListAgents(r.Context(), pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(agents))
}

type createAgentRequest struct {
	Name string `json:"name"`
	// ExpiresInHours bounds how long the enrollment token works. Default 24.
	ExpiresInHours int `json:"expiresInHours"`
}

type createAgentResponse struct {
	Agent *store.Agent `json:"agent"`
	// Token is shown only here. It works once.
	Token    string `json:"token"`
	CASHA256 string `json:"caSha256"`
	// Command enrolls the agent on the host.
	Command string `json:"command"`
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.AgentManage, o.ID, pr.ID) {
		return
	}
	if s.agentCA == nil {
		writeError(w, http.StatusServiceUnavailable, "agents_disabled", "the agent API is not enabled on this server")
		return
	}
	var req createAgentRequest
	if !decode(w, r, &req) || !validSlug(w, req.Name) {
		return
	}
	if req.ExpiresInHours <= 0 {
		req.ExpiresInHours = 24
	}
	if req.ExpiresInHours > 24*7 {
		writeError(w, http.StatusBadRequest, "bad_request", "enrollment tokens can last at most 168 hours")
		return
	}
	token, hash := auth.NewToken(agentapi.EnrollPrefix)
	a, err := s.store.CreateAgentInvitation(r.Context(), pr.ID, req.Name, hash, time.Now().Add(time.Duration(req.ExpiresInHours)*time.Hour))
	if err != nil {
		s.storeError(w, err, "agent")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "agent.invite", "agent", a.ID, nil, a)
	fp := s.agentCA.Fingerprint()
	writeJSON(w, http.StatusCreated, createAgentResponse{
		Agent: a, Token: token, CASHA256: fp,
		Command: fmt.Sprintf("certower-agent enroll -server %s -token %s -ca-sha256 %s", s.agentURL, token, fp),
	})
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.AgentManage, o.ID, pr.ID) {
		return
	}
	a, err := s.store.GetAgentByName(r.Context(), pr.ID, r.PathValue("agent"))
	if err == nil {
		err = s.store.DeleteAgent(r.Context(), a.ID)
	}
	if err != nil {
		s.storeError(w, err, "agent")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "agent.delete", "agent", a.ID, a, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- targets

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		return
	}
	ts, err := s.store.ListTargets(r.Context(), pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(ts))
}

type createTargetRequest struct {
	Name     string          `json:"name"`
	Agent    string          `json:"agent"`    // agent name
	Deployer string          `json:"deployer"` // files, nginx
	Settings json.RawMessage `json:"settings"`
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.TargetManage, o.ID, pr.ID) {
		return
	}
	var req createTargetRequest
	if !decode(w, r, &req) || !validSlug(w, req.Name) {
		return
	}
	// The agent re-checks paths and commands against its own allow-list;
	// this catches mistakes early.
	if _, err := agent.ResolveSettings(req.Deployer, req.Settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	a, err := s.store.GetAgentByName(r.Context(), pr.ID, req.Agent)
	if err != nil {
		s.storeError(w, err, "agent "+req.Agent)
		return
	}
	t, err := s.store.CreateTarget(r.Context(), store.Target{ProjectID: pr.ID, Name: req.Name, AgentID: a.ID, Deployer: req.Deployer, Settings: req.Settings})
	if err != nil {
		s.storeError(w, err, "target")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "target.create", "target", t.ID, nil, t)
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.TargetManage, o.ID, pr.ID) {
		return
	}
	t, err := s.store.GetTargetByName(r.Context(), pr.ID, r.PathValue("target"))
	if err == nil {
		err = s.store.DeleteTarget(r.Context(), t.ID)
	}
	if err != nil {
		s.storeError(w, err, "target")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "target.delete", "target", t.ID, t, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- certificate targets

func (s *Server) attachTarget(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, c, ok := s.certificate(w, r, p, rbac.CertDeploy)
	if !ok {
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t, err := s.store.GetTargetByName(ctx, pr.ID, req.Target)
	if err != nil {
		s.storeError(w, err, "target "+req.Target)
		return
	}
	if c.KeyLocation != "agent" {
		writeError(w, http.StatusConflict, "unsupported", "only certificates with keyLocation \"agent\" can be deployed by agents")
		return
	}
	// An agent-held key exists on exactly one host.
	existing, err := s.store.TargetsForCertificate(ctx, c.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, e := range existing {
		if e.AgentID != t.AgentID {
			writeError(w, http.StatusConflict, "different_agent", "this certificate's key lives on another agent; all its targets must be on that agent")
			return
		}
	}
	if err := s.store.AttachTarget(ctx, c.ID, t.ID); err != nil {
		s.storeError(w, err, "attachment")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "cert.attach", "certificate", c.ID, nil, map[string]string{"target": t.Name})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) detachTarget(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, c, ok := s.certificate(w, r, p, rbac.CertDeploy)
	if !ok {
		return
	}
	t, err := s.store.GetTargetByName(r.Context(), pr.ID, r.PathValue("target"))
	if err == nil {
		err = s.store.DetachTarget(r.Context(), c.ID, t.ID)
	}
	if err != nil {
		s.storeError(w, err, "attachment")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "cert.detach", "certificate", c.ID, map[string]string{"target": t.Name}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// deploymentView is the latest deployment state of one target.
type deploymentView struct {
	Target     string     `json:"target"`
	TargetID   string     `json:"targetId"`
	VersionID  string     `json:"versionId,omitempty"`
	Status     string     `json:"status"` // done, failed, or pending (nothing reported yet)
	Message    string     `json:"message,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	// Current reports whether the target has the certificate's current
	// version.
	Current bool `json:"current"`
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request, p *principal) {
	_, _, c, ok := s.certificate(w, r, p, rbac.CertRead)
	if !ok {
		return
	}
	ctx := r.Context()
	targets, err := s.store.TargetsForCertificate(ctx, c.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	deps, err := s.store.DeploymentsForCertificate(ctx, c.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	var curID string
	if cur, err := s.store.CurrentVersion(ctx, c.ID); err == nil {
		curID = cur.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	out := []deploymentView{}
	for _, t := range targets {
		v := deploymentView{Target: t.Name, TargetID: t.ID, Status: "pending"}
		for _, d := range deps { // newest first
			if d.TargetID == t.ID {
				finished := d.FinishedAt
				v.VersionID, v.Status, v.Message, v.FinishedAt = d.VersionID, d.Status, d.Message, &finished
				v.Current = d.VersionID == curID && d.Status == "done"
				break
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}
