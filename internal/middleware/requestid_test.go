package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddleware(t *testing.T) {
	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestID(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Request ID should be set in context.
	if capturedID == "" {
		t.Fatal("request ID not set in context")
	}

	// Request ID should be in response header.
	headerID := rec.Header().Get("X-Request-ID")
	if headerID == "" {
		t.Fatal("X-Request-ID response header not set")
	}

	if capturedID != headerID {
		t.Errorf("context ID %q != header ID %q", capturedID, headerID)
	}
}

func TestRequestIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids[GetRequestID(r.Context())] = true
	})

	handler := RequestID(inner)
	for range 100 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	if len(ids) != 100 {
		t.Errorf("expected 100 unique IDs, got %d", len(ids))
	}
}
