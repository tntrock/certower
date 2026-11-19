package api

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/store"
)

// endpointView is an endpoint with what was last seen on it.
type endpointView struct {
	store.DiscoveryEndpoint
	Certificate *store.DiscoveredCert `json:"certificate,omitempty"`
	// Managed names the Certower certificate the endpoint serves, if any.
	Managed *managedRef `json:"managed,omitempty"`
}

type managedRef struct {
	Project     string `json:"project"`
	Certificate string `json:"certificate"`
}

func (s *Server) listDiscovery(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok {
		return
	}
	ctx := r.Context()
	eps, err := s.store.ListEndpoints(ctx, o.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := []endpointView{}
	for _, ep := range eps {
		allowed, err := s.allowed(ctx, p, rbac.DiscoveryRead, o.ID, ep.ProjectID)
		if err != nil {
			s.internal(w, err)
			return
		}
		if !allowed {
			continue
		}
		v := endpointView{DiscoveryEndpoint: ep}
		if d, err := s.store.LatestDiscovered(ctx, ep.ID); err == nil {
			v.Certificate = d
			if d.VersionID != "" {
				v.Managed = s.managedRef(r, d)
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			s.internal(w, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) managedRef(r *http.Request, d *store.DiscoveredCert) *managedRef {
	v, err := s.store.VersionByFingerprint(r.Context(), d.Fingerprint)
	if err != nil {
		return nil
	}
	c, err := s.store.GetCertificate(r.Context(), v.CertificateID)
	if err != nil {
		return nil
	}
	pr, err := s.store.GetProject(r.Context(), c.ProjectID)
	if err != nil {
		return nil
	}
	return &managedRef{Project: pr.Slug, Certificate: c.Name}
}

type addEndpointsRequest struct {
	// Targets holds one endpoint per line or comma: host, host:port, or
	// [ipv6]:port. The port defaults to 443.
	Targets string `json:"targets"`
	// Project optionally assigns the endpoints to a project (slug).
	Project string `json:"project,omitempty"`
}

type addEndpointsResponse struct {
	Added   []store.DiscoveryEndpoint `json:"added"`
	Skipped []string                  `json:"skipped"`
}

// parseTarget splits "host[:port]" with port 443 by default.
func parseTarget(s string) (host string, port int, ok bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "tls://")
	s = strings.TrimSuffix(s, "/")
	if s == "" || strings.ContainsAny(s, " /\\@?#") {
		return "", 0, false
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		host, portStr = strings.Trim(s, "[]"), "443"
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || host == "" || len(host) > 253 {
		return "", 0, false
	}
	return strings.ToLower(host), port, true
}

func (s *Server) addDiscovery(w http.ResponseWriter, r *http.Request, p *principal) {
	o, ok := s.org(w, r, p)
	if !ok {
		return
	}
	var req addEndpointsRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	var projectID string
	if req.Project != "" {
		pr, err := s.store.GetProjectBySlug(ctx, o.ID, req.Project)
		if err == nil && !p.superuser() && !hasBinding(p, o.ID, pr.ID) {
			err = store.ErrNotFound
		}
		if err != nil {
			s.storeError(w, err, "project")
			return
		}
		projectID = pr.ID
	}
	if !s.require(w, r, p, rbac.DiscoveryManage, o.ID, projectID) {
		return
	}
	lines := strings.FieldsFunc(req.Targets, func(r rune) bool { return r == '\n' || r == ',' || r == '\r' })
	if len(lines) == 0 || len(lines) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "give between 1 and 1000 targets")
		return
	}
	resp := addEndpointsResponse{Added: []store.DiscoveryEndpoint{}, Skipped: []string{}}
	for _, line := range lines {
		host, port, ok := parseTarget(line)
		if !ok {
			resp.Skipped = append(resp.Skipped, strings.TrimSpace(line)+" (invalid)")
			continue
		}
		sni := ""
		if net.ParseIP(host) == nil {
			sni = host
		}
		ep, err := s.store.CreateEndpoint(ctx, store.DiscoveryEndpoint{OrgID: o.ID, ProjectID: projectID, Host: host, Port: port, SNI: sni})
		if errors.Is(err, store.ErrConflict) {
			resp.Skipped = append(resp.Skipped, net.JoinHostPort(host, strconv.Itoa(port))+" (already added)")
			continue
		} else if err != nil {
			s.internal(w, err)
			return
		}
		if _, err := s.engine.RequestScan(ctx, ep); err != nil {
			s.internal(w, err)
			return
		}
		resp.Added = append(resp.Added, *ep)
	}
	s.audit(r, p, o.ID, projectID, "discovery.add", "discovery_endpoint", "", nil, map[string]int{"added": len(resp.Added)})
	writeJSON(w, http.StatusCreated, resp)
}

// endpoint loads {id} and checks perm on its scope.
func (s *Server) endpoint(w http.ResponseWriter, r *http.Request, p *principal, perm rbac.Permission) (*store.DiscoveryEndpoint, bool) {
	o, ok := s.org(w, r, p)
	if !ok {
		return nil, false
	}
	ep, err := s.store.GetEndpoint(r.Context(), o.ID, r.PathValue("id"))
	if err != nil {
		s.storeError(w, err, "endpoint")
		return nil, false
	}
	return ep, s.require(w, r, p, perm, o.ID, ep.ProjectID)
}

func (s *Server) deleteDiscovery(w http.ResponseWriter, r *http.Request, p *principal) {
	ep, ok := s.endpoint(w, r, p, rbac.DiscoveryManage)
	if !ok {
		return
	}
	if err := s.store.DeleteEndpoint(r.Context(), ep.ID); err != nil {
		s.storeError(w, err, "endpoint")
		return
	}
	s.audit(r, p, ep.OrgID, ep.ProjectID, "discovery.delete", "discovery_endpoint", ep.ID, ep, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scanNow(w http.ResponseWriter, r *http.Request, p *principal) {
	ep, ok := s.endpoint(w, r, p, rbac.DiscoveryManage)
	if !ok {
		return
	}
	job, err := s.engine.RequestScan(r.Context(), ep)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// testNotifier sends a test event through a notifier configuration.
func (s *Server) testNotifier(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok || !s.require(w, r, p, rbac.IssuerManage, o.ID, projectID(pr)) {
		return
	}
	pc, ok := s.scopedConfig(w, r, o.ID, projectID(pr))
	if !ok {
		return
	}
	if pc.Kind != "notifier" {
		writeError(w, http.StatusBadRequest, "bad_request", "only notifiers can be tested")
		return
	}
	if err := s.engine.SendTest(r.Context(), pc); err != nil {
		writeError(w, http.StatusBadGateway, "delivery_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
