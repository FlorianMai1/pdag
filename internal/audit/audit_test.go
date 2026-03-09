package audit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/mai/pdag/internal/middleware"
)

type mockPublisher struct {
	mu      sync.Mutex
	entries []Entry
}

func (m *mockPublisher) Publish(e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func TestAuditMiddleware(t *testing.T) {
	pub := &mockPublisher{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.RequestID(Middleware(pub)(inner))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers?q=test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	pub.mu.Lock()
	defer pub.mu.Unlock()

	if len(pub.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(pub.entries))
	}
	got := pub.entries[0]

	if got.Method != "GET" {
		t.Errorf("method = %q, want GET", got.Method)
	}
	if got.Path != "/api/v1/servers" {
		t.Errorf("path = %q", got.Path)
	}
	if got.Query != "q=test" {
		t.Errorf("query = %q", got.Query)
	}
	if got.SourceIP != "10.0.0.1" {
		t.Errorf("source_ip = %q", got.SourceIP)
	}
	if got.UserAgent != "test-agent" {
		t.Errorf("user_agent = %q", got.UserAgent)
	}
	if got.StatusCode != 200 {
		t.Errorf("status_code = %d", got.StatusCode)
	}
	if got.RequestID == "" {
		t.Error("request_id is empty")
	}
}
