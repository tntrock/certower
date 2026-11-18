package api

import (
	"net/http"
	"strconv"

	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/store"
)

type slugName struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// ---------------------------------------------------------------- organizations

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request, p *principal) {
	all, err := s.store.ListOrganizations(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := []store.Organization{}
	for _, o := range all {
		if p.superuser() || hasBinding(p, o.ID, "") {
			out = append(out, o)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request, p *principal) {
	if !p.superuser() {
		writeError(w, http.StatusForbidden, "forbidden", "only instance administrators can create organizations")
		return
	}
	var req slugName
	if !decode(w, r, &req) || !validSlug(w, req.Slug) {
		return
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	o, err := s.store.CreateOrganization(r.Context(), req.Slug, req.Name)
	if err != nil {
		s.storeError(w, err, "organization")
		return
	}
	s.audit(r, p, o.ID, "", "org.create", "organization", o.ID, nil, o)
	writeJSON(w, http.StatusCreated, o)
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request, p *principal) {
	if o, ok := s.org(w, r, p); ok {
		writeJSON(w, http.StatusOK, o)
	}
}

// ---------------------------------------------------------------- projects

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok {
		return
	}
	all, err := s.store.ListProjects(r.Context(), o.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := []store.Project{}
	for _, pr := range all {
		ok, err := s.allowed(r.Context(), p, rbac.CertRead, o.ID, pr.ID)
		if err != nil {
			s.internal(w, err)
			return
		}
		if ok {
			out = append(out, pr)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok || !s.require(w, r, p, rbac.ProjectManage, o.ID, "") {
		return
	}
	var req slugName
	if !decode(w, r, &req) || !validSlug(w, req.Slug) {
		return
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	pr, err := s.store.CreateProject(r.Context(), o.ID, req.Slug, req.Name)
	if err != nil {
		s.storeError(w, err, "project")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "project.create", "project", pr.ID, nil, pr)
	writeJSON(w, http.StatusCreated, pr)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if ok && s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		writeJSON(w, http.StatusOK, pr)
	}
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.ProjectManage, o.ID, "") {
		return
	}
	if err := s.store.DeleteProject(r.Context(), pr.ID); err != nil {
		s.storeError(w, err, "project")
		return
	}
	s.audit(r, p, o.ID, "", "project.delete", "project", pr.ID, pr, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- policy

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		return
	}
	pol, err := s.store.GetPolicy(r.Context(), pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	// PolicyManage is organization-only: project admins cannot loosen their
	// own guardrails.
	if !ok || !s.require(w, r, p, rbac.PolicyManage, o.ID, pr.ID) {
		return
	}
	var pol policy.Policy
	if !decode(w, r, &pol) {
		return
	}
	if pol.MaxValidityDays < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "maxValidityDays must not be negative")
		return
	}
	before, err := s.store.GetPolicy(r.Context(), pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.PutPolicy(r.Context(), pr.ID, pol); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, p, o.ID, pr.ID, "policy.update", "policy", pr.ID, before, pol)
	writeJSON(w, http.StatusOK, pol)
}

// ---------------------------------------------------------------- audit log

// listAudit returns the organization's audit log, or one project's with
// ?project=<slug>. Paginate with ?before=<id>.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok {
		return
	}
	q := store.AuditQuery{OrgID: o.ID}
	if slug := r.URL.Query().Get("project"); slug != "" {
		pr, err := s.store.GetProjectBySlug(r.Context(), o.ID, slug)
		if err == nil && !p.superuser() && !hasBinding(p, o.ID, pr.ID) {
			err = store.ErrNotFound
		}
		if err != nil {
			s.storeError(w, err, "project")
			return
		}
		q.ProjectID = pr.ID
	}
	if !s.require(w, r, p, rbac.AuditRead, o.ID, q.ProjectID) {
		return
	}
	q.BeforeID, _ = strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	q.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.store.ListAudit(r.Context(), q)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(entries))
}
