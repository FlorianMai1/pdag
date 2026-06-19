package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mai/pdag/internal/clientip"
	"github.com/mai/pdag/internal/middleware"
)

// testResolver has no trusted proxies, so it resolves the client IP straight
// from RemoteAddr — matching the audit tests' RemoteAddr expectations.
var testResolver, _ = clientip.New(nil)

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

// reservingPublisher is a mockPublisher that also implements Reserver. reserveOK
// controls whether Reserve succeeds; committed entries are appended via Publish.
type reservingPublisher struct {
	mockPublisher
	reserveOK bool
}

func (m *reservingPublisher) Reserve(context.Context) (func(Entry), bool) {
	if !m.reserveOK {
		return nil, false
	}
	return func(e Entry) { _ = m.Publish(e) }, true
}

func TestAuditMiddlewareFailClosedRejectsWhenSaturated(t *testing.T) {
	pub := &reservingPublisher{reserveOK: false}

	var innerCalled bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.RequestID(Middleware(pub, Options{FailClosed: true}, testResolver)(inner))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/example.org.", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if innerCalled {
		t.Error("fail-closed: upstream handler must NOT be called when the audit pipeline is saturated")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.entries) != 0 {
		t.Errorf("got %d audit entries, want 0 (no reservation, no commit)", len(pub.entries))
	}
}

func TestAuditMiddlewareFailClosedCommitsWhenReserved(t *testing.T) {
	pub := &reservingPublisher{reserveOK: true}

	var innerCalled bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.RequestID(Middleware(pub, Options{FailClosed: true}, testResolver)(inner))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !innerCalled {
		t.Error("upstream handler should be called when reservation succeeds")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.entries) != 1 {
		t.Fatalf("got %d audit entries, want 1 (reserved + committed)", len(pub.entries))
	}
}

func TestAuditMiddleware(t *testing.T) {
	pub := &mockPublisher{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with a status code recorder to simulate what the metrics middleware
	// does in production (setting the StatusCodePtr in context).
	withStatusCode := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := middleware.NewStatusRecorder(w)
			ctx := middleware.WithStatusCodePtr(r.Context(), &rec.StatusCode)
			next.ServeHTTP(rec, r.WithContext(ctx))
		})
	}

	handler := middleware.RequestID(withStatusCode(Middleware(pub, Options{}, testResolver)(inner)))

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

func TestAuditMiddlewareLogsBody(t *testing.T) {
	pub := &mockPublisher{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	withStatusCode := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := middleware.NewStatusRecorder(w)
			ctx := middleware.WithStatusCodePtr(r.Context(), &rec.StatusCode)
			next.ServeHTTP(rec, r.WithContext(ctx))
		})
	}

	// Chain: audit(logBody=true) → bodyBuffer → inner
	handler := withStatusCode(Middleware(pub, Options{LogBody: true}, testResolver)(middleware.BodyBuffer(1 << 20)(inner)))

	body := `{"rrsets":[{"name":"example.com.","type":"A"}]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/example.com.", strings.NewReader(body))
	req.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	pub.mu.Lock()
	defer pub.mu.Unlock()

	if len(pub.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(pub.entries))
	}
	got := pub.entries[0]

	if got.RequestBody == nil {
		t.Fatal("request_body is nil, expected body to be logged")
	}
	if string(got.RequestBody) != body {
		t.Errorf("request_body = %s, want %s", got.RequestBody, body)
	}
}

func TestAuditMiddlewareOmitsBodyWhenDisabled(t *testing.T) {
	pub := &mockPublisher{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// logBody=false — should not capture body.
	handler := Middleware(pub, Options{}, testResolver)(middleware.BodyBuffer(1 << 20)(inner))

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"data":"test"}`))
	req.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	pub.mu.Lock()
	defer pub.mu.Unlock()

	if len(pub.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(pub.entries))
	}
	if pub.entries[0].RequestBody != nil {
		t.Errorf("request_body should be nil when logBody=false, got %s", pub.entries[0].RequestBody)
	}
}

func TestAuditTimestampIsCompletionTime(t *testing.T) {
	pub := &mockPublisher{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow handler so completion time differs from start.
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	withStatusCode := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := middleware.NewStatusRecorder(w)
			ctx := middleware.WithStatusCodePtr(r.Context(), &rec.StatusCode)
			next.ServeHTTP(rec, r.WithContext(ctx))
		})
	}

	handler := withStatusCode(Middleware(pub, Options{}, testResolver)(inner))

	before := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	after := time.Now()

	pub.mu.Lock()
	defer pub.mu.Unlock()

	if len(pub.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(pub.entries))
	}
	ts := pub.entries[0].Timestamp

	// Timestamp should be after the 50ms sleep, i.e. close to completion time.
	if ts.Before(before.Add(50 * time.Millisecond)) {
		t.Errorf("timestamp %v is before expected completion window (started %v + 50ms)", ts, before)
	}
	if ts.After(after) {
		t.Errorf("timestamp %v is after test completion %v", ts, after)
	}
}
