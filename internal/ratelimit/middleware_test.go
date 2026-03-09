package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/ratelimit"
	"github.com/mai/pdag/internal/ratelimit/token"
)

func TestMiddlewareAllows(t *testing.T) {
	limiter := token.New(token.Config{Rate: 100, Burst: 10})
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ratelimit.Middleware(limiter)(inner)
	ctx := middleware.WithPrincipal(context.Background(), "alice")
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("inner handler should be called")
	}
}

func TestMiddleware429(t *testing.T) {
	limiter := token.New(token.Config{Rate: 1, Burst: 1})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := ratelimit.Middleware(limiter)(inner)
	ctx := middleware.WithPrincipal(context.Background(), "bob")

	// First request — allowed.
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first request: status = %d, want 200", rec.Code)
	}

	// Second request — rate limited.
	req = httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want 1", rec.Header().Get("Retry-After"))
	}
}

func TestMiddlewareNoPrincipal(t *testing.T) {
	limiter := token.New(token.Config{Rate: 1, Burst: 1})
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ratelimit.Middleware(limiter)(inner)
	// No principal in context — should pass through without rate limiting.
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("inner handler should be called for unauthenticated requests")
	}
}

func TestMiddlewarePerPrincipalIsolation(t *testing.T) {
	limiter := token.New(token.Config{Rate: 1, Burst: 1})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := ratelimit.Middleware(limiter)(inner)

	// Alice exhausts her limit.
	ctx := middleware.WithPrincipal(context.Background(), "alice")
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	req = httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("alice second: status = %d, want 429", rec.Code)
	}

	// Bob should still be allowed.
	ctx = middleware.WithPrincipal(context.Background(), "bob")
	req = httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("bob first: status = %d, want 200", rec.Code)
	}
}
