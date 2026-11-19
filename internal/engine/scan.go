package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tntrock/certower/internal/certutil"
	"github.com/tntrock/certower/internal/discovery"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// JobScan scans one discovery endpoint.
const JobScan = "scan"

type scanPayload struct {
	EndpointID string `json:"endpointId"`
}

// RequestScan queues a scan of an endpoint.
func (e *Engine) RequestScan(ctx context.Context, ep *store.DiscoveryEndpoint) (*store.Job, error) {
	e.init()
	payload, _ := json.Marshal(scanPayload{EndpointID: ep.ID})
	j, _, err := e.Store.EnqueueJob(ctx, store.Job{ProjectID: ep.ProjectID, Type: JobScan, Payload: payload, DedupeKey: "scan:" + ep.ID})
	if err == nil {
		e.notify()
	}
	return j, err
}

func (e *Engine) scheduleScans(ctx context.Context) error {
	due, err := e.Store.EndpointsDue(ctx, e.Now().Add(-e.ScanEvery), 500)
	if err != nil {
		return err
	}
	for i := range due {
		if _, err := e.RequestScan(ctx, &due[i]); err != nil {
			return err
		}
	}
	return nil
}

// runScan connects to the endpoint and records what it serves. Connection
// failures are recorded on the endpoint rather than retried: the next
// scheduled scan tries again.
func (e *Engine) runScan(ctx context.Context, j *store.Job) error {
	var p scanPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return permanent(err)
	}
	ep, err := e.Store.GetEndpointByID(ctx, p.EndpointID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // deleted meanwhile
	} else if err != nil {
		return err
	}
	res, err := e.Scanner.Scan(ctx, ep.Host, ep.Port, ep.SNI, discovery.Options{Now: e.Now()})
	if err != nil {
		return e.Store.RecordScan(ctx, ep.ID, err.Error())
	}

	leaf := res.Chain[0]
	fp := certutil.Fingerprint(leaf.Raw)
	var versionID string
	if v, err := e.Store.VersionByFingerprint(ctx, fp); err == nil {
		versionID = v.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	findings, _ := json.Marshal(nonNilFindings(res.Findings))
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if _, err := e.Store.UpsertDiscovered(ctx, store.DiscoveredCert{
		EndpointID: ep.ID, Fingerprint: fp, Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
		Names: names, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Findings: findings, VersionID: versionID,
	}); err != nil {
		return err
	}
	if err := e.Store.RecordScan(ctx, ep.ID, ""); err != nil {
		return err
	}

	// Announce each critical problem once per certificate and endpoint.
	// Expiry of managed certificates is announced by checkExpiry instead.
	for _, f := range res.Findings {
		if f.Severity != discovery.Critical || (versionID != "" && (f.Code == discovery.CodeExpired || f.Code == discovery.CodeExpiringSoon)) {
			continue
		}
		where := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		ev := plugin.Event{
			Type: plugin.EventDiscoveryAlert, Severity: plugin.SeverityCritical,
			Subject: fmt.Sprintf("%s: %s", where, f.Message),
			Body: fmt.Sprintf("Certificate for %s issued by %s, valid until %s.\nFinding: %s (%s)",
				strings.Join(names, ", "), leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format("2006-01-02"), f.Message, f.Code),
			Link: "/o/" + e.orgSlug(ctx, ep.OrgID) + "/discovery",
		}
		if err := e.Notify(ctx, ep.OrgID, ep.ProjectID, ev, fmt.Sprintf("discovery:%s:%s:%s", ep.ID, fp, f.Code)); err != nil {
			return err
		}
	}
	return nil
}

func nonNilFindings(fs []discovery.Finding) []discovery.Finding {
	if fs == nil {
		return []discovery.Finding{}
	}
	return fs
}

func (e *Engine) orgSlug(ctx context.Context, orgID string) string {
	if o, err := e.Store.GetOrganization(ctx, orgID); err == nil {
		return o.Slug
	}
	return ""
}
