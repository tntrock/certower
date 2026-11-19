package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// Job type for delivering one event to one notifier.
const JobNotify = "notify"

// maxNotifyAttempts bounds retries of a failing notifier.
const maxNotifyAttempts = 8

type notifyPayload struct {
	ConfigID string       `json:"configId"`
	Event    plugin.Event `json:"event"`
}

var severityRank = map[plugin.Severity]int{plugin.SeverityInfo: 0, plugin.SeverityWarning: 1, plugin.SeverityCritical: 2}

// notifierFilter holds the delivery filters every notifier config may set.
type notifierFilter struct {
	Events      []string        `json:"events"`
	MinSeverity plugin.Severity `json:"minSeverity"`
}

func (f notifierFilter) wants(ev plugin.Event) bool {
	if len(f.Events) > 0 && !slices.Contains(f.Events, string(ev.Type)) {
		return false
	}
	return severityRank[ev.Severity] >= severityRank[f.MinSeverity]
}

// Notify queues ev for every notifier of the organization and of the
// project (if any) whose filters accept it. With a dedupeKey, an event is
// delivered only the first time it is raised.
func (e *Engine) Notify(ctx context.Context, orgID, projectID string, ev plugin.Event, dedupeKey string) error {
	e.init()
	if dedupeKey != "" {
		first, err := e.Store.LogNotification(ctx, dedupeKey)
		if err != nil || !first {
			return err
		}
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	org, err := e.Store.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}
	ev.Org = org.Slug
	if projectID != "" {
		p, err := e.Store.GetProject(ctx, projectID)
		if err != nil {
			return err
		}
		ev.Project = p.Slug
	}
	if ev.Link != "" && e.BaseURL != "" {
		ev.Link = e.BaseURL + ev.Link
	} else if e.BaseURL == "" {
		ev.Link = ""
	}

	configs, err := e.Store.ListPluginConfigs(ctx, orgID, projectID)
	if err != nil {
		return err
	}
	for _, c := range configs {
		if c.Kind != string(plugin.KindNotifier) {
			continue
		}
		var f notifierFilter
		json.Unmarshal(c.Config, &f)
		if !f.wants(ev) {
			continue
		}
		payload, _ := json.Marshal(notifyPayload{ConfigID: c.ID, Event: ev})
		if _, _, err := e.Store.EnqueueJob(ctx, store.Job{ProjectID: projectID, Type: JobNotify, Payload: payload}); err != nil {
			return err
		}
	}
	e.notify()
	return nil
}

func (e *Engine) runNotify(ctx context.Context, j *store.Job) error {
	var p notifyPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return permanent(err)
	}
	pc, err := e.Store.GetPluginConfig(ctx, p.ConfigID)
	if errors.Is(err, store.ErrNotFound) {
		return permanent(errors.New("notifier was deleted"))
	} else if err != nil {
		return err
	}
	inst, err := e.Configs.Instantiate(ctx, pc)
	if err != nil {
		return permanent(err)
	}
	n, ok := inst.(plugin.Notifier)
	if !ok {
		return permanent(fmt.Errorf("config %q is not a notifier", pc.Name))
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := n.Notify(ctx, p.Event); err != nil {
		if j.Attempts >= maxNotifyAttempts {
			return permanent(fmt.Errorf("giving up after %d attempts: %w", j.Attempts, err))
		}
		return err
	}
	return nil
}

// SendTest delivers a test event to one notifier immediately.
func (e *Engine) SendTest(ctx context.Context, pc *store.PluginConfig) error {
	inst, err := e.Configs.Instantiate(ctx, pc)
	if err != nil {
		return err
	}
	n, ok := inst.(plugin.Notifier)
	if !ok {
		return fmt.Errorf("config %q is not a notifier", pc.Name)
	}
	org, err := e.Store.GetOrganization(ctx, pc.OrgID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return n.Notify(ctx, plugin.Event{
		Type: "test", Severity: plugin.SeverityInfo, Time: time.Now().UTC(), Org: org.Slug,
		Subject: "Test notification from Certower",
		Body:    fmt.Sprintf("Notifier %q is configured correctly.", pc.Name),
	})
}

// expiryThresholds are the days before expiry at which to warn, once each.
var expiryThresholds = []int{21, 14, 7, 3, 1}

// checkExpiry warns about current versions approaching expiry. Each version
// gets one notification per threshold it crosses.
func (e *Engine) checkExpiry(ctx context.Context) error {
	now := e.Now()
	versions, err := e.Store.ExpiringVersions(ctx, now.Add(time.Duration(expiryThresholds[0])*24*time.Hour))
	if err != nil {
		return err
	}
	for _, v := range versions {
		cert, err := e.Store.GetCertificate(ctx, v.CertificateID)
		if err != nil {
			continue
		}
		left := v.NotAfter.Sub(now)
		days := int(math.Ceil(left.Hours() / 24))
		var bucket int
		for _, t := range expiryThresholds {
			if days <= t {
				bucket = t
			}
		}
		sev := plugin.SeverityInfo
		subject := fmt.Sprintf("%s expires in %d days", cert.Name, days)
		key := fmt.Sprintf("expiring:%s:%d", v.ID, bucket)
		switch {
		case left <= 0:
			sev, key = plugin.SeverityCritical, "expired:"+v.ID
			subject = fmt.Sprintf("%s has expired", cert.Name)
		case days <= 3:
			sev = plugin.SeverityCritical
		case days <= 14:
			sev = plugin.SeverityWarning
		}
		body := fmt.Sprintf("Certificate %s %v expires on %s.", cert.Name, cert.Names, v.NotAfter.UTC().Format(time.RFC1123))
		if cert.LastError != "" {
			body += "\nRenewal is failing: " + cert.LastError
		}
		e.NotifyCertificate(ctx, cert, plugin.EventCertExpiring, sev, subject, body, key)
	}
	return nil
}

// NotifyCertificate raises an event about a certificate. With a dedupeKey
// it is raised only once.
func (e *Engine) NotifyCertificate(ctx context.Context, cert *store.Certificate, typ plugin.EventType, sev plugin.Severity, subject, body, dedupeKey string) {
	p, err := e.Store.GetProject(ctx, cert.ProjectID)
	if err != nil {
		return
	}
	org, err := e.Store.GetOrganization(ctx, p.OrgID)
	if err != nil {
		return
	}
	ev := plugin.Event{Type: typ, Severity: sev, Subject: subject, Body: body,
		Link: fmt.Sprintf("/o/%s/p/%s/certificates/%s", org.Slug, p.Slug, cert.Name)}
	if err := e.Notify(ctx, p.OrgID, p.ID, ev, dedupeKey); err != nil {
		e.Log.Error("notify", "event", typ, "err", err)
	}
}
