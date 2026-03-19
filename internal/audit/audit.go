package audit

import (
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

// noop is a Publisher that silently discards all entries.
type noop struct{}

func (noop) Publish(Entry) error { return nil }

// Noop returns a Publisher that discards all entries.
func Noop() Publisher { return noop{} }
