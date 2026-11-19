package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/store"
)

// ---------------------------------------------------------------- users

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, p *principal) {
	if !p.superuser() {
		writeError(w, http.StatusForbidden, "forbidden", "only instance administrators can list users")
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(users))
}

type createUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	IsSuperuser bool   `json:"isSuperuser"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, p *principal) {
	if !p.superuser() {
		writeError(w, http.StatusForbidden, "forbidden", "only instance administrators can create users")
		return
	}
	var req createUserRequest
	if !decode(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "bad_request", "a valid email is required")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	u, err := s.store.CreateUser(r.Context(), email, req.DisplayName, hash, req.IsSuperuser)
	if err != nil {
		s.storeError(w, err, "user")
		return
	}
	s.audit(r, p, "", "", "user.create", "user", u.ID, nil, u)
	writeJSON(w, http.StatusCreated, u)
}

// ---------------------------------------------------------------- roles

type roleInfo struct {
	Name        string            `json:"name"`
	Builtin     bool              `json:"builtin"`
	Permissions []rbac.Permission `json:"permissions"`
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok {
		return
	}
	a, err := s.authorizer(r.Context(), o.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	var out []roleInfo
	for _, role := range rbac.BuiltinRoles() {
		out = append(out, roleInfo{Name: string(role), Builtin: true, Permissions: a.Permissions(role)})
	}
	custom, err := s.store.ListCustomRoles(r.Context(), o.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, c := range custom {
		out = append(out, roleInfo{Name: c.Name, Permissions: a.Permissions(rbac.Role(c.Name))})
	}
	writeJSON(w, http.StatusOK, out)
}

type createRoleRequest struct {
	Name        string            `json:"name"`
	Permissions []rbac.Permission `json:"permissions"`
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok || !s.require(w, r, p, rbac.MemberManage, o.ID, "") {
		return
	}
	var req createRoleRequest
	if !decode(w, r, &req) || !validSlug(w, strings.ReplaceAll(req.Name, "_", "-")) {
		return
	}
	if rbac.IsBuiltin(rbac.Role(req.Name)) {
		writeError(w, http.StatusConflict, "conflict", "a built-in role has that name")
		return
	}
	if len(req.Permissions) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "at least one permission is required")
		return
	}
	perms := make([]string, len(req.Permissions))
	for i, perm := range req.Permissions {
		if !rbac.IsPermission(perm) {
			writeError(w, http.StatusBadRequest, "bad_request", "unknown permission "+string(perm))
			return
		}
		perms[i] = string(perm)
	}
	role, err := s.store.CreateCustomRole(r.Context(), o.ID, req.Name, perms)
	if err != nil {
		s.storeError(w, err, "role")
		return
	}
	s.audit(r, p, o.ID, "", "role.create", "role", role.ID, nil, role)
	writeJSON(w, http.StatusCreated, role)
}

// ---------------------------------------------------------------- role bindings

// bindingScope resolves the organization and, on project routes, the
// project a binding route operates on.
func (s *Server) bindingScope(w http.ResponseWriter, r *http.Request, p *principal) (*store.Organization, *store.Project, bool) {
	if r.PathValue("project") == "" {
		o, ok := s.org(w, r, p)
		return o, nil, ok
	}
	return s.project(w, r, p)
}

func projectID(pr *store.Project) string {
	if pr == nil {
		return ""
	}
	return pr.ID
}

func (s *Server) listBindings(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok || !s.require(w, r, p, rbac.MemberManage, o.ID, projectID(pr)) {
		return
	}
	bs, err := s.store.ListRoleBindings(r.Context(), o.ID, projectID(pr))
	if err != nil {
		s.internal(w, err)
		return
	}
	// Show people by email rather than ID.
	emails := map[string]string{}
	for i, b := range bs {
		if b.UserID == "" {
			continue
		}
		if _, ok := emails[b.UserID]; !ok {
			if u, err := s.store.GetUser(r.Context(), b.UserID); err == nil {
				emails[b.UserID] = u.Email
			}
		}
		bs[i].UserEmail = emails[b.UserID]
	}
	writeJSON(w, http.StatusOK, nonNil(bs))
}

type createBindingRequest struct {
	Role string `json:"role"`
	// Exactly one subject:
	User           string `json:"user,omitempty"`           // email
	ServiceAccount string `json:"serviceAccount,omitempty"` // name, project bindings only
	OIDCGroup      string `json:"oidcGroup,omitempty"`
}

// canGrant reports whether p holds every permission of role in the scope,
// so nobody can hand out more than they have.
func (s *Server) canGrant(r *http.Request, p *principal, a *rbac.Authorizer, role rbac.Role, orgID, projectID string) (bool, error) {
	for _, perm := range a.Permissions(role) {
		ok, err := s.allowed(r.Context(), p, perm, orgID, projectID)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (s *Server) createBinding(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok || !s.require(w, r, p, rbac.MemberManage, o.ID, projectID(pr)) {
		return
	}
	var req createBindingRequest
	if !decode(w, r, &req) {
		return
	}
	subjects := 0
	for _, v := range []string{req.User, req.ServiceAccount, req.OIDCGroup} {
		if v != "" {
			subjects++
		}
	}
	if subjects != 1 {
		writeError(w, http.StatusBadRequest, "bad_request", "specify exactly one of user, serviceAccount, oidcGroup")
		return
	}

	a, err := s.authorizer(r.Context(), o.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	role := rbac.Role(req.Role)
	if !a.HasRole(role) {
		writeError(w, http.StatusBadRequest, "bad_request", "unknown role "+req.Role)
		return
	}
	if ok, err := s.canGrant(r, p, a, role, o.ID, projectID(pr)); err != nil {
		s.internal(w, err)
		return
	} else if !ok {
		writeError(w, http.StatusForbidden, "forbidden", "you cannot grant a role with permissions you do not hold")
		return
	}

	b := store.RoleBinding{OrgID: o.ID, ProjectID: projectID(pr), Role: req.Role, OIDCGroup: req.OIDCGroup}
	switch {
	case req.User != "":
		u, err := s.store.GetUserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(req.User)))
		if err != nil {
			s.storeError(w, err, "user")
			return
		}
		b.UserID = u.ID
	case req.ServiceAccount != "":
		if pr == nil {
			writeError(w, http.StatusBadRequest, "bad_request", "service accounts can only be bound to their own project")
			return
		}
		sa, err := s.store.GetServiceAccountByName(r.Context(), pr.ID, req.ServiceAccount)
		if err != nil {
			s.storeError(w, err, "service account")
			return
		}
		b.ServiceAccountID = sa.ID
	}
	created, err := s.store.CreateRoleBinding(r.Context(), b)
	if err != nil {
		s.storeError(w, err, "binding")
		return
	}
	s.audit(r, p, o.ID, b.ProjectID, "binding.create", "role_binding", created.ID, nil, created)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) deleteBinding(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok || !s.require(w, r, p, rbac.MemberManage, o.ID, projectID(pr)) {
		return
	}
	b, err := s.store.GetRoleBinding(r.Context(), o.ID, r.PathValue("id"))
	if err == nil && b.ProjectID != projectID(pr) {
		err = store.ErrNotFound // binding belongs to a different scope
	}
	if err != nil {
		s.storeError(w, err, "binding")
		return
	}
	a, err := s.authorizer(r.Context(), o.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if ok, err := s.canGrant(r, p, a, rbac.Role(b.Role), o.ID, b.ProjectID); err != nil {
		s.internal(w, err)
		return
	} else if !ok {
		writeError(w, http.StatusForbidden, "forbidden", "you cannot revoke a role with permissions you do not hold")
		return
	}
	if err := s.store.DeleteRoleBinding(r.Context(), o.ID, b.ID); err != nil {
		s.storeError(w, err, "binding")
		return
	}
	s.audit(r, p, o.ID, b.ProjectID, "binding.delete", "role_binding", b.ID, b, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- service accounts

func (s *Server) listServiceAccounts(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.TokenManage, o.ID, pr.ID) {
		return
	}
	sas, err := s.store.ListServiceAccounts(r.Context(), pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(sas))
}

func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.TokenManage, o.ID, pr.ID) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) || !validSlug(w, req.Name) {
		return
	}
	sa, err := s.store.CreateServiceAccount(r.Context(), pr.ID, req.Name)
	if err != nil {
		s.storeError(w, err, "service account")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "service_account.create", "service_account", sa.ID, nil, sa)
	writeJSON(w, http.StatusCreated, sa)
}

func (s *Server) deleteServiceAccount(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.TokenManage, o.ID, pr.ID) {
		return
	}
	sa, err := s.store.GetServiceAccountByName(r.Context(), pr.ID, r.PathValue("sa"))
	if err == nil {
		err = s.store.DeleteServiceAccount(r.Context(), sa.ID)
	}
	if err != nil {
		s.storeError(w, err, "service account")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "service_account.delete", "service_account", sa.ID, sa, nil)
	w.WriteHeader(http.StatusNoContent)
}

type createTokenRequest struct {
	// ExpiresInDays of 0 means the token never expires.
	ExpiresInDays int `json:"expiresInDays"`
}

type createTokenResponse struct {
	*store.APIToken
	// Token is only ever returned here.
	Token string `json:"token"`
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.TokenManage, o.ID, pr.ID) {
		return
	}
	var req createTokenRequest
	if !decode(w, r, &req) {
		return
	}
	if req.ExpiresInDays < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "expiresInDays must not be negative")
		return
	}
	sa, err := s.store.GetServiceAccountByName(r.Context(), pr.ID, r.PathValue("sa"))
	if err != nil {
		s.storeError(w, err, "service account")
		return
	}
	var expires *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour).UTC()
		expires = &t
	}
	token, hash := auth.NewToken(auth.APITokenPrefix)
	t, err := s.store.CreateAPIToken(r.Context(), sa.ID, hash, expires)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, p, o.ID, pr.ID, "token.create", "api_token", t.ID, nil, t)
	writeJSON(w, http.StatusCreated, createTokenResponse{APIToken: t, Token: token})
}
