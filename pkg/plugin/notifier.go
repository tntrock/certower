package plugin

import (
	"context"
	"time"
)

// Severity of an event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// EventType names what happened.
type EventType string

const (
	EventCertExpiring   EventType = "cert.expiring"
	EventCertIssued     EventType = "cert.issued"
	EventIssueFailed    EventType = "cert.issue_failed"
	EventDeployed       EventType = "cert.deployed"
	EventDeployFailed   EventType = "cert.deploy_failed"
	EventManualAction   EventType = "cert.manual_action"
	EventDiscoveryAlert EventType = "discovery.finding"
	EventAgentOffline   EventType = "agent.offline"
)

// Event is delivered to Notifiers.
type Event struct {
	Type     EventType         `json:"type"`
	Severity Severity          `json:"severity"`
	Time     time.Time         `json:"time"`
	Org      string            `json:"org"`
	Project  string            `json:"project,omitempty"`
	Subject  string            `json:"subject"`
	Body     string            `json:"body"`
	Link     string            `json:"link,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// Notifier delivers events.
type Notifier interface {
	Plugin
	Notify(ctx context.Context, event Event) error
}
