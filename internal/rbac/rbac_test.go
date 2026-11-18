package rbac

import "testing"

func TestAllowed(t *testing.T) {
	a := New(map[Role][]Permission{
		"key_custodian": {KeyExport, CertRead},
	})
	shop := Resource{OrgID: "acme", ProjectID: "shop"}
	erp := Resource{OrgID: "acme", ProjectID: "erp"}
	org := Resource{OrgID: "acme"}
	otherOrg := Resource{OrgID: "evil", ProjectID: "shop"}

	tests := []struct {
		name     string
		bindings []Binding
		perm     Permission
		res      Resource
		want     bool
	}{
		{"org admin reaches every project", []Binding{{Role: OrgAdmin, OrgID: "acme"}}, CertIssue, erp, true},
		{"org admin manages policy", []Binding{{Role: OrgAdmin, OrgID: "acme"}}, PolicyManage, org, true},
		{"binding does not cross orgs", []Binding{{Role: OrgAdmin, OrgID: "acme"}}, CertRead, otherOrg, false},
		{"operator issues in own project", []Binding{{Role: Operator, OrgID: "acme", ProjectID: "shop"}}, CertIssue, shop, true},
		{"operator has nothing in other project", []Binding{{Role: Operator, OrgID: "acme", ProjectID: "shop"}}, CertRead, erp, false},
		{"operator cannot manage secrets", []Binding{{Role: Operator, OrgID: "acme", ProjectID: "shop"}}, SecretManage, shop, false},
		{"operator can use secrets", []Binding{{Role: Operator, OrgID: "acme", ProjectID: "shop"}}, SecretUse, shop, true},
		{"viewer is read-only", []Binding{{Role: Viewer, OrgID: "acme", ProjectID: "shop"}}, CertIssue, shop, false},
		{"viewer cannot use secrets", []Binding{{Role: Viewer, OrgID: "acme", ProjectID: "shop"}}, SecretUse, shop, false},
		{"auditor reads audit log", []Binding{{Role: Auditor, OrgID: "acme"}}, AuditRead, shop, true},
		{"project admin cannot change policy", []Binding{{Role: ProjectAdmin, OrgID: "acme", ProjectID: "shop"}}, PolicyManage, shop, false},
		{"no built-in role exports keys", []Binding{{Role: OrgAdmin, OrgID: "acme"}}, KeyExport, shop, false},
		{"custom role exports keys", []Binding{{Role: "key_custodian", OrgID: "acme", ProjectID: "shop"}}, KeyExport, shop, true},
		{"unknown role grants nothing", []Binding{{Role: "nope", OrgID: "acme"}}, CertRead, shop, false},
		{"any binding is enough", []Binding{
			{Role: Viewer, OrgID: "acme", ProjectID: "shop"},
			{Role: Operator, OrgID: "acme", ProjectID: "shop"},
		}, CertDeploy, shop, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Allowed(tt.bindings, tt.perm, tt.res); got != tt.want {
				t.Errorf("Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCustomRoleCannotOverrideBuiltin(t *testing.T) {
	a := New(map[Role][]Permission{Viewer: {KeyExport}})
	if a.Allowed([]Binding{{Role: Viewer, OrgID: "o"}}, KeyExport, Resource{OrgID: "o"}) {
		t.Fatal("custom role definition overrode built-in viewer")
	}
}
