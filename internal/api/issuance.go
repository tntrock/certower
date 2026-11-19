package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/tntrock/certower/internal/pluginconfig"
	"github.com/tntrock/certower/internal/policy"
	"github.com/tntrock/certower/internal/rbac"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// ---------------------------------------------------------------- plugins

func (s *Server) listPlugins(w http.ResponseWriter, r *http.Request, p *principal) {
	out := map[plugin.Kind][]plugin.Meta{}
	for _, k := range []plugin.Kind{plugin.KindIssuer, plugin.KindDNS, plugin.KindDeployer, plugin.KindNotifier} {
		out[k] = nonNil(s.configs.Registry.List(k))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- configs

func (s *Server) listConfigs(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok {
		return
	}
	if pr != nil && !s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		return
	}
	cs, err := s.store.ListPluginConfigs(r.Context(), o.ID, projectID(pr))
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]store.PluginConfig, len(cs))
	for i, c := range cs {
		out[i] = pluginconfig.Redact(c)
	}
	writeJSON(w, http.StatusOK, out)
}

type createConfigRequest struct {
	Kind   plugin.Kind     `json:"kind"`
	Plugin string          `json:"plugin"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

// configPerms must all be held to create or delete a configuration: it
// both defines an integration and stores its secrets.
var configPerms = []rbac.Permission{rbac.IssuerManage, rbac.SecretManage}

func (s *Server) requireAll(w http.ResponseWriter, r *http.Request, p *principal, perms []rbac.Permission, orgID, projectID string) bool {
	for _, perm := range perms {
		if !s.require(w, r, p, perm, orgID, projectID) {
			return false
		}
	}
	return true
}

func (s *Server) createConfig(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok || !s.requireAll(w, r, p, configPerms, o.ID, projectID(pr)) {
		return
	}
	var req createConfigRequest
	if !decode(w, r, &req) || !validSlug(w, req.Name) {
		return
	}
	pc, err := s.configs.Create(r.Context(), pluginconfig.CreateRequest{
		OrgID: o.ID, ProjectID: projectID(pr), Kind: req.Kind, Plugin: req.Plugin, Name: req.Name, Config: req.Config,
	})
	if errors.Is(err, pluginconfig.ErrInvalid) {
		writeError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	} else if err != nil {
		s.storeError(w, err, "configuration")
		return
	}
	red := pluginconfig.Redact(*pc)
	s.audit(r, p, o.ID, projectID(pr), "config.create", "plugin_config", pc.ID, nil, red)
	writeJSON(w, http.StatusCreated, red)
}

// scopedConfig loads {config} and checks it belongs exactly to the route's
// scope, so a project route cannot touch organization-wide configurations.
func (s *Server) scopedConfig(w http.ResponseWriter, r *http.Request, orgID, projectID string) (*store.PluginConfig, bool) {
	pc, err := s.store.GetPluginConfig(r.Context(), r.PathValue("config"))
	if err == nil && (pc.OrgID != orgID || pc.ProjectID != projectID) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.storeError(w, err, "configuration")
		return nil, false
	}
	return pc, true
}

func (s *Server) deleteConfig(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.bindingScope(w, r, p)
	if !ok || !s.requireAll(w, r, p, configPerms, o.ID, projectID(pr)) {
		return
	}
	pc, ok := s.scopedConfig(w, r, o.ID, projectID(pr))
	if !ok {
		return
	}
	if err := s.configs.Delete(r.Context(), pc); errors.Is(err, store.ErrInvalidReference) {
		writeError(w, http.StatusConflict, "in_use", "configuration is used by certificates or targets")
		return
	} else if err != nil {
		s.storeError(w, err, "configuration")
		return
	}
	s.audit(r, p, o.ID, projectID(pr), "config.delete", "plugin_config", pc.ID, pluginconfig.Redact(*pc), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- certificates

// certificateView is a certificate with its current version, if any.
type certificateView struct {
	store.Certificate
	Current *store.CertificateVersion `json:"current,omitempty"`
}

func (s *Server) view(r *http.Request, c store.Certificate) (certificateView, error) {
	v := certificateView{Certificate: c}
	cur, err := s.store.CurrentVersion(r.Context(), c.ID)
	if err == nil {
		v.Current = cur
	} else if !errors.Is(err, store.ErrNotFound) {
		return v, err
	}
	return v, nil
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		return
	}
	certs, err := s.store.ListCertificates(r.Context(), pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]certificateView, 0, len(certs))
	for _, c := range certs {
		v, err := s.view(r, c)
		if err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

type createCertificateRequest struct {
	Name       string   `json:"name"`
	Names      []string `json:"names"`
	KeyType    string   `json:"keyType,omitempty"`
	Issuer     string   `json:"issuer"`        // issuer configuration name
	DNS        string   `json:"dns,omitempty"` // DNS configuration name
	Profile    string   `json:"profile,omitempty"`
	OwnerEmail string   `json:"ownerEmail,omitempty"`
	// KeyLocation is "server" (default) or "agent". Agent keys are
	// generated on the host and never leave it; issuance starts once a
	// target on an agent is attached.
	KeyLocation string `json:"keyLocation,omitempty"`
}

var supportedKeyTypes = []policy.KeyType{policy.ECDSAP256, policy.ECDSAP384, policy.RSA2048, policy.RSA3072, policy.RSA4096}

func normalizeNames(names []string) ([]string, bool) {
	var out []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" || strings.ContainsAny(n, " /\\") {
			return nil, false
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, len(out) > 0
}

func (s *Server) createCertificate(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	// Issuing uses the issuer's and DNS provider's stored credentials.
	if !ok || !s.requireAll(w, r, p, []rbac.Permission{rbac.CertIssue, rbac.SecretUse}, o.ID, pr.ID) {
		return
	}
	var req createCertificateRequest
	if !decode(w, r, &req) || !validSlug(w, req.Name) {
		return
	}
	names, ok := normalizeNames(req.Names)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "names must be a non-empty list of DNS names")
		return
	}
	if req.KeyType == "" {
		req.KeyType = string(policy.ECDSAP256)
	}
	if !slices.Contains(supportedKeyTypes, policy.KeyType(req.KeyType)) {
		writeError(w, http.StatusBadRequest, "bad_request", "unsupported keyType "+req.KeyType)
		return
	}
	switch req.KeyLocation {
	case "":
		req.KeyLocation = "server"
	case "server", "agent":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "keyLocation must be server or agent")
		return
	}

	ctx := r.Context()
	issuer, err := s.store.FindPluginConfig(ctx, o.ID, pr.ID, string(plugin.KindIssuer), req.Issuer)
	if err != nil {
		s.storeError(w, err, "issuer "+req.Issuer)
		return
	}
	if ip, err := s.configs.Registry.New(plugin.KindIssuer, issuer.Plugin); err == nil && ip.Meta().RequiresDNS && req.DNS == "" {
		writeError(w, http.StatusBadRequest, "dns_required", "issuer "+issuer.Name+" validates with DNS-01: set dns to a DNS configuration")
		return
	}
	var dnsID string
	if req.DNS != "" {
		dns, err := s.store.FindPluginConfig(ctx, o.ID, pr.ID, string(plugin.KindDNS), req.DNS)
		if err != nil {
			s.storeError(w, err, "DNS configuration "+req.DNS)
			return
		}
		dnsID = dns.ID
	}

	pol, err := s.store.GetPolicy(ctx, pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if vs := pol.Check(policy.Request{Names: names, IssuerID: issuer.Name, KeyType: policy.KeyType(req.KeyType)}); len(vs) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":      apiError{Code: "policy_violation", Message: "the request breaks the project's policy"},
			"violations": vs,
		})
		return
	}

	c, err := s.store.CreateCertificate(ctx, store.Certificate{
		ProjectID: pr.ID, Name: req.Name, Names: names, KeyType: req.KeyType,
		IssuerConfigID: issuer.ID, DNSConfigID: dnsID, Profile: req.Profile,
		KeyLocation: req.KeyLocation, OwnerEmail: req.OwnerEmail,
	})
	if err != nil {
		s.storeError(w, err, "certificate")
		return
	}
	if c.KeyLocation == "agent" {
		s.audit(r, p, o.ID, pr.ID, "cert.create", "certificate", c.ID, nil, c)
		writeJSON(w, http.StatusCreated, map[string]any{"certificate": c})
		return
	}
	job, err := s.engine.RequestIssue(ctx, c)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, p, o.ID, pr.ID, "cert.create", "certificate", c.ID, nil, c)
	writeJSON(w, http.StatusAccepted, map[string]any{"certificate": c, "job": job})
}

// certificate loads {org}/{project}/{cert} and checks perm on the project.
func (s *Server) certificate(w http.ResponseWriter, r *http.Request, p *principal, perm rbac.Permission) (*store.Organization, *store.Project, *store.Certificate, bool) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, perm, o.ID, pr.ID) {
		return nil, nil, nil, false
	}
	c, err := s.store.GetCertificateByName(r.Context(), pr.ID, r.PathValue("cert"))
	if err != nil {
		s.storeError(w, err, "certificate")
		return nil, nil, nil, false
	}
	return o, pr, c, true
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request, p *principal) {
	_, _, c, ok := s.certificate(w, r, p, rbac.CertRead)
	if !ok {
		return
	}
	v, err := s.view(r, *c)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// deleteCertificate stops managing a certificate and erases its stored
// keys. It does not revoke anything; revoke first if needed.
func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, c, ok := s.certificate(w, r, p, rbac.CertRevoke)
	if !ok {
		return
	}
	ctx := r.Context()
	versions, err := s.store.ListVersions(ctx, c.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	err = s.store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.DeleteCertificate(ctx, c.ID); err != nil {
			return err
		}
		for _, v := range versions {
			if v.KeySecretID == "" {
				continue
			}
			if err := s.vault.WithStore(tx).Delete(ctx, v.KeySecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.storeError(w, err, "certificate")
		return
	}
	s.audit(r, p, o.ID, pr.ID, "cert.delete", "certificate", c.ID, c, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, c, ok := s.certificate(w, r, p, rbac.CertIssue)
	if !ok || !s.require(w, r, p, rbac.SecretUse, o.ID, pr.ID) {
		return
	}
	if c.Status == store.CertInvalid {
		// Someone presumably fixed the cause; let the scheduler see it again.
		if err := s.store.SetCertificateStatus(r.Context(), c.ID, store.CertPending, ""); err != nil {
			s.internal(w, err)
			return
		}
	}
	if c.KeyLocation == "agent" {
		// The agent generates the new key and sends a CSR on its next sync.
		if err := s.store.RequestRenewal(r.Context(), c.ID); err != nil {
			s.internal(w, err)
			return
		}
		s.audit(r, p, o.ID, pr.ID, "cert.renew", "certificate", c.ID, nil, nil)
		writeJSON(w, http.StatusAccepted, map[string]string{"waitingFor": "agent"})
		return
	}
	job, err := s.engine.RequestIssue(r.Context(), c)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, p, o.ID, pr.ID, "cert.renew", "certificate", c.ID, nil, map[string]string{"job": job.ID})
	writeJSON(w, http.StatusAccepted, job)
}

type revokeRequest struct {
	// Version defaults to the current version.
	Version string `json:"version,omitempty"`
	// Reason is an RFC 5280 reason code.
	Reason int `json:"reason"`
}

// Reason codes subscribers may use under the CA/Browser Forum Baseline
// Requirements: unspecified, keyCompromise, affiliationChanged,
// superseded, cessationOfOperation.
var allowedRevokeReasons = []int{0, 1, 3, 4, 5}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, c, ok := s.certificate(w, r, p, rbac.CertRevoke)
	if !ok {
		return
	}
	var req revokeRequest
	if !decode(w, r, &req) {
		return
	}
	if !slices.Contains(allowedRevokeReasons, req.Reason) {
		writeError(w, http.StatusBadRequest, "bad_request", "reason must be one of 0, 1, 3, 4, 5 (RFC 5280)")
		return
	}
	ctx := r.Context()
	var v *store.CertificateVersion
	var err error
	if req.Version == "" {
		v, err = s.store.CurrentVersion(ctx, c.ID)
	} else {
		v, err = s.store.GetVersion(ctx, c.ID, req.Version)
	}
	if err != nil {
		s.storeError(w, err, "certificate version")
		return
	}
	if v.RevokedAt != nil {
		writeError(w, http.StatusConflict, "already_revoked", "this version is already revoked")
		return
	}
	if err := s.engine.Revoke(ctx, c, v, req.Reason); err != nil {
		s.log.Warn("revocation failed", "certificate", c.ID, "err", err)
		writeError(w, http.StatusBadGateway, "ca_error", "the CA refused or failed the revocation: "+err.Error())
		return
	}
	s.audit(r, p, o.ID, pr.ID, "cert.revoke", "certificate", c.ID, nil, map[string]any{"version": v.ID, "reason": req.Reason})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request, p *principal) {
	_, _, c, ok := s.certificate(w, r, p, rbac.CertRead)
	if !ok {
		return
	}
	vs, err := s.store.ListVersions(r.Context(), c.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(vs))
}

// version loads {version}; "current" means the newest unrevoked one.
func (s *Server) version(w http.ResponseWriter, r *http.Request, c *store.Certificate) (*store.CertificateVersion, bool) {
	var v *store.CertificateVersion
	var err error
	if id := r.PathValue("version"); id == "current" {
		v, err = s.store.CurrentVersion(r.Context(), c.ID)
	} else {
		v, err = s.store.GetVersion(r.Context(), c.ID, id)
	}
	if err != nil {
		s.storeError(w, err, "certificate version")
		return nil, false
	}
	return v, true
}

func (s *Server) downloadChain(w http.ResponseWriter, r *http.Request, p *principal) {
	_, _, c, ok := s.certificate(w, r, p, rbac.CertRead)
	if !ok {
		return
	}
	v, ok := s.version(w, r, c)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write([]byte(v.ChainPEM))
}

func (s *Server) downloadKey(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, c, ok := s.certificate(w, r, p, rbac.KeyExport)
	if !ok {
		return
	}
	v, ok := s.version(w, r, c)
	if !ok {
		return
	}
	if v.KeySecretID == "" {
		writeError(w, http.StatusNotFound, "not_found", "the private key is not held by the server")
		return
	}
	key, err := s.vault.GetScoped(r.Context(), v.KeySecretID, o.ID, pr.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, p, o.ID, pr.ID, "key.export", "certificate_version", v.ID, nil, nil)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(key)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request, p *principal) {
	o, pr, ok := s.project(w, r, p)
	if !ok || !s.require(w, r, p, rbac.CertRead, o.ID, pr.ID) {
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), pr.ID, 50)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(jobs))
}
