// Package api serves Certower's REST API under /api/v1.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/capresets"
	"github.com/tntrock/certower/internal/engine"
	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/internal/version"
)

// SessionCookie carries the session token for the web UI.
const SessionCookie = "certower_session"

// Server holds the API's dependencies.
type Server struct {
	store   *store.Store
	log     *slog.Logger
	engine  *engine.Engine
	configs *pluginconfig.Service
	vault   *secrets.Vault

	// SessionTTL is how long a login lasts. Default 12h.
	SessionTTL time.Duration
	// SecureCookies sets the Secure flag on the session cookie. Enable it
	// whenever the UI is served over HTTPS.
	SecureCookies bool
}

// Deps are the services the API uses.
type Deps struct {
	Store   *store.Store
	Log     *slog.Logger
	Engine  *engine.Engine
	Configs *pluginconfig.Service
	Vault   *secrets.Vault
}

// New returns a Server.
func New(d Deps) *Server {
	return &Server{store: d.Store, log: d.Log, engine: d.Engine, configs: d.Configs, vault: d.Vault, SessionTTL: 12 * time.Hour}
}

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	pub := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, h) }
	priv := func(pattern string, h handler) { mux.Handle(pattern, s.authed(h)) }

	pub("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	pub("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": version.Version, "commit": version.Commit})
	})
	pub("GET /api/v1/ca-presets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, capresets.All())
	})
	pub("POST /api/v1/auth/login", s.login)

	priv("POST /api/v1/auth/logout", s.logout)
	priv("GET /api/v1/me", s.me)

	priv("GET /api/v1/users", s.listUsers)
	priv("POST /api/v1/users", s.createUser)

	priv("GET /api/v1/orgs", s.listOrgs)
	priv("POST /api/v1/orgs", s.createOrg)
	priv("GET /api/v1/orgs/{org}", s.getOrg)
	priv("GET /api/v1/orgs/{org}/audit", s.listAudit)

	priv("GET /api/v1/orgs/{org}/roles", s.listRoles)
	priv("POST /api/v1/orgs/{org}/roles", s.createRole)
	priv("GET /api/v1/orgs/{org}/bindings", s.listBindings)
	priv("POST /api/v1/orgs/{org}/bindings", s.createBinding)
	priv("DELETE /api/v1/orgs/{org}/bindings/{id}", s.deleteBinding)

	priv("GET /api/v1/orgs/{org}/projects", s.listProjects)
	priv("POST /api/v1/orgs/{org}/projects", s.createProject)
	priv("GET /api/v1/orgs/{org}/projects/{project}", s.getProject)
	priv("DELETE /api/v1/orgs/{org}/projects/{project}", s.deleteProject)
	priv("GET /api/v1/orgs/{org}/projects/{project}/policy", s.getPolicy)
	priv("PUT /api/v1/orgs/{org}/projects/{project}/policy", s.putPolicy)
	priv("GET /api/v1/orgs/{org}/projects/{project}/bindings", s.listBindings)
	priv("POST /api/v1/orgs/{org}/projects/{project}/bindings", s.createBinding)
	priv("DELETE /api/v1/orgs/{org}/projects/{project}/bindings/{id}", s.deleteBinding)
	priv("GET /api/v1/orgs/{org}/projects/{project}/service-accounts", s.listServiceAccounts)
	priv("POST /api/v1/orgs/{org}/projects/{project}/service-accounts", s.createServiceAccount)
	priv("DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{sa}", s.deleteServiceAccount)
	priv("POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{sa}/tokens", s.createToken)

	priv("GET /api/v1/plugins", s.listPlugins)
	priv("GET /api/v1/orgs/{org}/configs", s.listConfigs)
	priv("POST /api/v1/orgs/{org}/configs", s.createConfig)
	priv("DELETE /api/v1/orgs/{org}/configs/{config}", s.deleteConfig)
	priv("GET /api/v1/orgs/{org}/projects/{project}/configs", s.listConfigs)
	priv("POST /api/v1/orgs/{org}/projects/{project}/configs", s.createConfig)
	priv("DELETE /api/v1/orgs/{org}/projects/{project}/configs/{config}", s.deleteConfig)

	priv("GET /api/v1/orgs/{org}/projects/{project}/certificates", s.listCertificates)
	priv("POST /api/v1/orgs/{org}/projects/{project}/certificates", s.createCertificate)
	priv("GET /api/v1/orgs/{org}/projects/{project}/certificates/{cert}", s.getCertificate)
	priv("DELETE /api/v1/orgs/{org}/projects/{project}/certificates/{cert}", s.deleteCertificate)
	priv("POST /api/v1/orgs/{org}/projects/{project}/certificates/{cert}/renew", s.renewCertificate)
	priv("POST /api/v1/orgs/{org}/projects/{project}/certificates/{cert}/revoke", s.revokeCertificate)
	priv("GET /api/v1/orgs/{org}/projects/{project}/certificates/{cert}/versions", s.listVersions)
	priv("GET /api/v1/orgs/{org}/projects/{project}/certificates/{cert}/versions/{version}/chain.pem", s.downloadChain)
	priv("GET /api/v1/orgs/{org}/projects/{project}/certificates/{cert}/versions/{version}/key.pem", s.downloadKey)
	priv("GET /api/v1/orgs/{org}/projects/{project}/jobs", s.listJobs)

	return mux
}

// ---------------------------------------------------------------- authentication

// principal is the authenticated caller.
type principal struct {
	user      *store.User           // set for humans
	sa        *store.ServiceAccount // set for service accounts
	bindings  []store.RoleBinding
	viaCookie bool
	token     string
}

func (p *principal) superuser() bool { return p.user != nil && p.user.IsSuperuser }

func (p *principal) actor() (typ, id string) {
	if p.sa != nil {
		return "service_account", p.sa.ID
	}
	return "user", p.user.ID
}

type handler func(w http.ResponseWriter, r *http.Request, p *principal)

func (s *Server) authed(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, viaCookie := bearer(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "missing credentials")
			return
		}
		if viaCookie && !safeMethod(r.Method) && !isJSON(r) {
			// Cross-site forms cannot send application/json without a CORS
			// preflight, which we never approve. Together with SameSite=Strict
			// this blocks CSRF.
			writeError(w, http.StatusForbidden, "csrf", "cookie-authenticated requests must use application/json")
			return
		}
		p, err := s.resolve(r.Context(), token)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid or expired credentials")
			return
		} else if err != nil {
			s.internal(w, err)
			return
		}
		p.viaCookie = viaCookie
		h(w, r, p)
	})
}

func (s *Server) resolve(ctx context.Context, token string) (*principal, error) {
	hash := auth.HashToken(token)
	p := &principal{token: token}
	var err error
	switch {
	case strings.HasPrefix(token, auth.SessionPrefix):
		if p.user, err = s.store.SessionUser(ctx, hash); err != nil {
			return nil, err
		}
		p.bindings, err = s.store.BindingsForUser(ctx, p.user.ID, nil)
	case strings.HasPrefix(token, auth.APITokenPrefix):
		if p.sa, err = s.store.TokenServiceAccount(ctx, hash); err != nil {
			return nil, err
		}
		p.bindings, err = s.store.BindingsForServiceAccount(ctx, p.sa.ID)
	default:
		return nil, store.ErrNotFound
	}
	return p, err
}

func bearer(r *http.Request) (token string, viaCookie bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		if t, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(t), false
		}
		return "", false
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value, true
	}
	return "", false
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func isJSON(r *http.Request) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return mt == "application/json"
}

// ---------------------------------------------------------------- authorization

// authorizer builds the role table for an organization, including its
// custom roles.
func (s *Server) authorizer(ctx context.Context, orgID string) (*rbac.Authorizer, error) {
	custom, err := s.store.ListCustomRoles(ctx, orgID)
	if err != nil {
		return nil, err
	}
	m := make(map[rbac.Role][]rbac.Permission, len(custom))
	for _, c := range custom {
		perms := make([]rbac.Permission, len(c.Permissions))
		for i, p := range c.Permissions {
			perms[i] = rbac.Permission(p)
		}
		m[rbac.Role(c.Name)] = perms
	}
	return rbac.New(m), nil
}

func rbacBindings(bs []store.RoleBinding) []rbac.Binding {
	out := make([]rbac.Binding, len(bs))
	for i, b := range bs {
		out[i] = rbac.Binding{Role: rbac.Role(b.Role), OrgID: b.OrgID, ProjectID: b.ProjectID}
	}
	return out
}

// allowed reports whether p holds perm on the organization (projectID "")
// or on one project. Superusers hold everything except key export, which
// must always be granted explicitly.
func (s *Server) allowed(ctx context.Context, p *principal, perm rbac.Permission, orgID, projectID string) (bool, error) {
	if p.superuser() && perm != rbac.KeyExport {
		return true, nil
	}
	a, err := s.authorizer(ctx, orgID)
	if err != nil {
		return false, err
	}
	return a.Allowed(rbacBindings(p.bindings), perm, rbac.Resource{OrgID: orgID, ProjectID: projectID}), nil
}

// require writes 403 and returns false unless p holds perm.
func (s *Server) require(w http.ResponseWriter, r *http.Request, p *principal, perm rbac.Permission, orgID, projectID string) bool {
	ok, err := s.allowed(r.Context(), p, perm, orgID, projectID)
	if err != nil {
		s.internal(w, err)
		return false
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden", "missing permission "+string(perm))
	}
	return ok
}

// org loads the {org} path value. Callers with no binding in the
// organization get 404, so organization names cannot be probed.
func (s *Server) org(w http.ResponseWriter, r *http.Request, p *principal) (*store.Organization, bool) {
	o, err := s.store.GetOrganizationBySlug(r.Context(), r.PathValue("org"))
	if err == nil && !p.superuser() && !hasBinding(p, o.ID, "") {
		err = store.ErrNotFound
	}
	if err != nil {
		s.storeError(w, err, "organization")
		return nil, false
	}
	return o, true
}

// project loads {org} and {project}. Callers who can see neither the whole
// organization nor this project get 404.
func (s *Server) project(w http.ResponseWriter, r *http.Request, p *principal) (*store.Organization, *store.Project, bool) {
	o, ok := s.org(w, r, p)
	if !ok {
		return nil, nil, false
	}
	pr, err := s.store.GetProjectBySlug(r.Context(), o.ID, r.PathValue("project"))
	if err == nil && !p.superuser() && !hasBinding(p, o.ID, pr.ID) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.storeError(w, err, "project")
		return nil, nil, false
	}
	return o, pr, true
}

// hasBinding reports whether p has any binding that reaches the given
// organization (projectID "") or project.
func hasBinding(p *principal, orgID, projectID string) bool {
	for _, b := range p.bindings {
		if b.OrgID != orgID {
			continue
		}
		if projectID == "" || b.ProjectID == "" || b.ProjectID == projectID {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- audit

func (s *Server) audit(r *http.Request, p *principal, orgID, projectID, action, objType, objID string, before, after any) {
	typ, id := p.actor()
	e := store.AuditEntry{
		OrgID: orgID, ProjectID: projectID, ActorType: typ, ActorID: id,
		Action: action, ObjectType: objType, ObjectID: objID,
		Before: marshalOrNil(before), After: marshalOrNil(after),
		SourceIP: clientIP(r),
	}
	if err := s.store.InsertAudit(r.Context(), e); err != nil {
		// The action already happened. Losing its audit record is serious,
		// but failing the request now would mislead the caller.
		s.log.Error("audit write failed", "err", err, "action", action, "object", objID)
	}
}

func marshalOrNil(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// clientIP is the TCP peer. X-Forwarded-For is not trusted until trusted
// proxies are configurable.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// ---------------------------------------------------------------- JSON helpers

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg}})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func (s *Server) storeError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", what+" not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", what+" already exists")
	case errors.Is(err, store.ErrInvalidReference):
		writeError(w, http.StatusBadRequest, "invalid_reference", what+" refers to something that does not exist")
	default:
		s.internal(w, err)
	}
}

// decode reads a JSON body into v, rejecting unknown fields.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validSlug(w http.ResponseWriter, slug string) bool {
	if !slugRe.MatchString(slug) {
		writeError(w, http.StatusBadRequest, "invalid_slug", "slug must be 1-63 lowercase letters, digits or dashes, not starting or ending with a dash")
		return false
	}
	return true
}
