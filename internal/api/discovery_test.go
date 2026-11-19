package api

import (
	"testing"
)

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]struct {
		host string
		port int
		ok   bool
	}{
		"www.example.com":          {"www.example.com", 443, true},
		"WWW.Example.com:8443":     {"www.example.com", 8443, true},
		"https://www.example.com/": {"www.example.com", 443, true},
		"10.0.0.5":                 {"10.0.0.5", 443, true},
		"[2001:db8::1]:636":        {"2001:db8::1", 636, true},
		"2001:db8::1":              {"2001:db8::1", 443, true},
		"host:0":                   {"", 0, false},
		"host:99999":               {"", 0, false},
		"user@host":                {"", 0, false},
		"a b":                      {"", 0, false},
		"":                         {"", 0, false},
	} {
		host, port, ok := parseTarget(in)
		if ok != want.ok || host != want.host || port != want.port {
			t.Errorf("parseTarget(%q) = %q, %d, %v; want %q, %d, %v", in, host, port, ok, want.host, want.port, want.ok)
		}
	}
}

func TestDiscoveryAPI(t *testing.T) {
	e := newEnv(t)
	root := e.user("root@example.com", true)
	ops := e.user("ops@example.com", false)
	e.do(root, "POST", "/api/v1/orgs", slugName{Slug: "acme"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects", slugName{Slug: "web"}, 201, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/projects/web/bindings", createBindingRequest{Role: "operator", User: "ops@example.com"}, 201, nil)

	// Operators read discovery but cannot add endpoints.
	e.do(ops, "POST", "/api/v1/orgs/acme/discovery", addEndpointsRequest{Targets: "a.example.com", Project: "web"}, 403, nil)

	var res addEndpointsResponse
	e.do(root, "POST", "/api/v1/orgs/acme/discovery", addEndpointsRequest{Targets: "www.example.com\nmail.example.com:465, bad host\nwww.example.com"}, 201, &res)
	if len(res.Added) != 2 || len(res.Skipped) != 2 {
		t.Fatalf("added %d skipped %v", len(res.Added), res.Skipped)
	}
	e.do(root, "POST", "/api/v1/orgs/acme/discovery", addEndpointsRequest{Targets: "shop.example.com", Project: "web"}, 201, nil)

	// The operator sees only the project's endpoint; the org admin all.
	var mine, all []endpointView
	e.do(ops, "GET", "/api/v1/orgs/acme/discovery", nil, 200, &mine)
	e.do(root, "GET", "/api/v1/orgs/acme/discovery", nil, 200, &all)
	if len(mine) != 1 || mine[0].Host != "shop.example.com" || len(all) != 3 {
		t.Fatalf("operator sees %v, admin sees %d", mine, len(all))
	}
	e.do(ops, "DELETE", "/api/v1/orgs/acme/discovery/"+all[0].ID, nil, 403, nil)
	e.do(root, "POST", "/api/v1/orgs/acme/discovery/"+all[0].ID+"/scan", nil, 202, nil)
	e.do(root, "DELETE", "/api/v1/orgs/acme/discovery/"+all[0].ID, nil, 204, nil)
}
