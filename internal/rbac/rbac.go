// Package rbac decides who may do what in which organization or project.
package rbac

import "slices"

// Permission is a single action on a resource type.
type Permission string

const (
	CertRead   Permission = "cert.read"
	CertIssue  Permission = "cert.issue" // request, renew, upload manual certs
	CertRevoke Permission = "cert.revoke"
	CertDeploy Permission = "cert.deploy"
	// KeyExport allows downloading server-held private keys. No built-in
	// role has it; it must be granted explicitly by a custom role.
	KeyExport Permission = "key.export"

	TargetManage Permission = "target.manage"
	AgentManage  Permission = "agent.manage"

	IssuerManage Permission = "issuer.manage"
	// SecretUse allows referencing a stored secret (e.g. a DNS API key) in
	// a configuration. Secret values are never readable through the API.
	SecretUse    Permission = "secret.use"
	SecretManage Permission = "secret.manage" // create, rotate, delete

	PolicyManage  Permission = "policy.manage"
	MemberManage  Permission = "member.manage"
	ProjectManage Permission = "project.manage"
	TokenManage   Permission = "token.manage"

	DiscoveryRead   Permission = "discovery.read"
	DiscoveryManage Permission = "discovery.manage"

	AuditRead Permission = "audit.read"
)

// Role is a named set of permissions.
type Role string

const (
	OrgAdmin     Role = "org_admin"
	ProjectAdmin Role = "project_admin"
	Operator     Role = "operator"
	Viewer       Role = "viewer"
	Auditor      Role = "auditor"
)

var (
	viewerPerms = []Permission{CertRead, DiscoveryRead}

	operatorPerms = append([]Permission{
		CertIssue, CertRevoke, CertDeploy, SecretUse,
	}, viewerPerms...)

	projectAdminPerms = append([]Permission{
		TargetManage, AgentManage, IssuerManage, SecretManage,
		MemberManage, TokenManage, DiscoveryManage, AuditRead,
	}, operatorPerms...)

	orgAdminPerms = append([]Permission{
		PolicyManage, ProjectManage,
	}, projectAdminPerms...)

	auditorPerms = append([]Permission{AuditRead}, viewerPerms...)
)

var builtin = map[Role]map[Permission]bool{
	OrgAdmin:     set(orgAdminPerms),
	ProjectAdmin: set(projectAdminPerms),
	Operator:     set(operatorPerms),
	Viewer:       set(viewerPerms),
	Auditor:      set(auditorPerms),
}

// orgOnly permissions only take effect from an organization-level binding,
// so a project admin cannot loosen the guardrails placed on their project.
var orgOnly = map[Permission]bool{
	PolicyManage:  true,
	ProjectManage: true,
}

func set(ps []Permission) map[Permission]bool {
	m := make(map[Permission]bool, len(ps))
	for _, p := range ps {
		m[p] = true
	}
	return m
}

// Binding grants a role to a subject in an organization, or in one project
// of it when ProjectID is set.
type Binding struct {
	Role      Role
	OrgID     string
	ProjectID string // empty: applies to the whole organization
}

// Resource locates the object being acted on. ProjectID is empty for
// organization-level objects such as policies or shared issuers.
type Resource struct {
	OrgID     string
	ProjectID string
}

// Authorizer resolves roles to permissions. Custom roles can be added on top
// of the built-in ones.
type Authorizer struct {
	roles map[Role]map[Permission]bool
}

// New returns an Authorizer with the built-in roles plus any custom roles.
// A custom role may not reuse a built-in name.
func New(custom map[Role][]Permission) *Authorizer {
	roles := make(map[Role]map[Permission]bool, len(builtin)+len(custom))
	for r, ps := range builtin {
		roles[r] = ps
	}
	for r, ps := range custom {
		if _, exists := builtin[r]; exists {
			continue
		}
		roles[r] = set(ps)
	}
	return &Authorizer{roles: roles}
}

// Allowed reports whether any of the bindings grants perm on res.
func (a *Authorizer) Allowed(bindings []Binding, perm Permission, res Resource) bool {
	for _, b := range bindings {
		if b.OrgID != res.OrgID {
			continue
		}
		if b.ProjectID != "" {
			if orgOnly[perm] || b.ProjectID != res.ProjectID {
				continue
			}
		}
		if a.roles[b.Role][perm] {
			return true
		}
	}
	return false
}

// Permissions returns the permissions of a role, sorted.
func (a *Authorizer) Permissions(r Role) []Permission {
	out := make([]Permission, 0, len(a.roles[r]))
	for p := range a.roles[r] {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// HasRole reports whether r is a built-in or configured custom role.
func (a *Authorizer) HasRole(r Role) bool {
	_, ok := a.roles[r]
	return ok
}

// BuiltinRoles lists the built-in roles, most privileged first.
func BuiltinRoles() []Role {
	return []Role{OrgAdmin, ProjectAdmin, Operator, Viewer, Auditor}
}

// IsBuiltin reports whether r is a built-in role.
func IsBuiltin(r Role) bool {
	_, ok := builtin[r]
	return ok
}

// AllPermissions lists every known permission.
func AllPermissions() []Permission {
	return []Permission{
		CertRead, CertIssue, CertRevoke, CertDeploy, KeyExport,
		TargetManage, AgentManage, IssuerManage, SecretUse, SecretManage,
		PolicyManage, MemberManage, ProjectManage, TokenManage,
		DiscoveryRead, DiscoveryManage, AuditRead,
	}
}

// IsPermission reports whether p is a known permission.
func IsPermission(p Permission) bool {
	return slices.Contains(AllPermissions(), p)
}
