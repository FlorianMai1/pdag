package audit

import (
	"context"
	"encoding/json"
	"time"
)

// Entry represents a single audit log line.
type Entry struct {
	Timestamp     time.Time       `json:"timestamp"`
	RequestID     string          `json:"request_id"`
	Principal     string          `json:"principal,omitempty"`
	KeyID         string          `json:"key_id,omitempty"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	Query         string          `json:"query,omitempty"`
	SourceIP      string          `json:"source_ip"`
	UserAgent     string          `json:"user_agent,omitempty"`
	StatusCode    int             `json:"status_code"`
	LatencyMs     int64           `json:"latency_ms"`
	AuthzDecision string          `json:"authz_decision,omitempty"`
	AuthzPlugin   string          `json:"authz_plugin,omitempty"`
	AuthzReason   string          `json:"authz_reason,omitempty"`
	RequestBody   json.RawMessage `json:"request_body,omitempty"`
}

// Publisher accepts audit entries for persistent storage.
// Implementations handle buffering, encoding, and delivery.
type Publisher interface {
	Publish(Entry) error
}

// Reserver is an optional capability for Publishers that support reserving
// buffer capacity ahead of time. It enables fail-closed audit mode: the audit
// middleware reserves a slot BEFORE the upstream call, so a saturated audit
// pipeline rejects the request (503) rather than letting an unaudited mutation
// through.
type Reserver interface {
	// Reserve blocks (up to an implementation-defined timeout, also bounded by
	// ctx) to acquire one buffer slot. On success it returns a commit function
	// that must be called exactly once with the final entry, and ok=true. On
	// failure (pipeline saturated or closed) it returns a nil commit and
	// ok=false.
	Reserve(ctx context.Context) (commit func(Entry), ok bool)
}

// noop is a Publisher that silently discards all entries.
type noop struct{}

func (noop) Publish(Entry) error { return nil }

// Reserve implements Reserver: it always succeeds with a no-op commit so
// fail-closed mode degrades to a no-op when auditing is disabled.
func (noop) Reserve(context.Context) (func(Entry), bool) {
	return func(Entry) {}, true
}

// Noop returns a Publisher that discards all entries.
func Noop() Publisher { return noop{} }
