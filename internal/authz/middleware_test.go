package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mai/pdag/internal/middleware"
	pb "github.com/mai/pdag/proto/authz"
)

// stubAuthorizer implements Authorizer for testing.
type stubAuthorizer struct {
	decision string
	plugin   string
	reason   string
}

func (s *stubAuthorizer) Authorize(_ context.Context, _ []string, req *pb.HttpRequest) (string, string, string) {
	// Check that X-Api-Key is redacted before reaching the plugin.
	for _, h := range req.Headers {
		if http.CanonicalHeaderKey(h.Key) == "X-Api-Key" {
			if len(h.Values) > 0 && h.Values[0] != "REDACTED" {
				return "deny", "test", "api key was not redacted: " + h.Values[0]
			}
		}
	}
	return s.decision, s.plugin, s.reason
}

func TestAuthzMiddlewareAllow(t *testing.T) {
	authz := &stubAuthorizer{decision: "allow", plugin: "admin", reason: "full access"}
	var innerCalled bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Set up context with roles and authz result pointer.
	var result middleware.AuthzResult
	ctx := middleware.WithRoles(context.Background(), []string{"admin"})
	ctx = middleware.WithAuthzResultPtr(ctx, &result)

	handler := Middleware(authz)(inner)
	req := httptest.NewRequest("GET", "/api/v1/servers", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !innerCalled {
		t.Error("inner handler was not called on allow")
	}
	if result.Decision != "allow" {
		t.Errorf("result.Decision = %q, want allow", result.Decision)
	}
}

func TestAuthzMiddlewareDeny(t *testing.T) {
	authz := &stubAuthorizer{decision: "deny", plugin: "read_zones", reason: "method not allowed"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called on deny")
	})

	var result middleware.AuthzResult
	ctx := middleware.WithRoles(context.Background(), []string{"read_zones"})
	ctx = middleware.WithAuthzResultPtr(ctx, &result)

	handler := Middleware(authz)(inner)
	req := httptest.NewRequest("DELETE", "/api/v1/servers/localhost/zones/x", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if result.Decision != "deny" {
		t.Errorf("result.Decision = %q, want deny", result.Decision)
	}
}

func TestAuthzMiddlewareNoRoles(t *testing.T) {
	authz := &stubAuthorizer{decision: "allow"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called with no roles")
	})

	var result middleware.AuthzResult
	ctx := middleware.WithAuthzResultPtr(context.Background(), &result)
	// No roles set.

	handler := Middleware(authz)(inner)
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if result.Decision != "deny" {
		t.Errorf("result.Decision = %q, want deny", result.Decision)
	}
}

func TestAuthzMiddlewareRedactsApiKey(t *testing.T) {
	authz := &stubAuthorizer{decision: "allow", plugin: "admin", reason: "ok"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var result middleware.AuthzResult
	ctx := middleware.WithRoles(context.Background(), []string{"admin"})
	ctx = middleware.WithAuthzResultPtr(ctx, &result)

	handler := Middleware(authz)(inner)
	req := httptest.NewRequest("GET", "/api/v1/servers", nil).WithContext(ctx)
	req.Header.Set("X-API-Key", "k_secret:pdg_plaintext_secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; reason: %s", rec.Code, result.Reason)
	}
}

func TestAuthzMiddlewareNoResultPtr(t *testing.T) {
	// When audit middleware is disabled, there's no authz result pointer.
	// The middleware should not panic.
	authz := &stubAuthorizer{decision: "deny", plugin: "test", reason: "no ptr"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called")
	})

	ctx := middleware.WithRoles(context.Background(), []string{"test"})
	// No WithAuthzResultPtr.

	handler := Middleware(authz)(inner)
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
