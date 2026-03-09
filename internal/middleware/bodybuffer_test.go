package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyBufferNormal(t *testing.T) {
	var ctxBody []byte
	var downstreamBody string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxBody = GetBodyBytes(r.Context())
		b, _ := io.ReadAll(r.Body)
		downstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyBuffer(1024)(inner)
	body := `{"test": "data"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if string(ctxBody) != body {
		t.Errorf("context body = %q, want %q", string(ctxBody), body)
	}
	if downstreamBody != body {
		t.Errorf("downstream body = %q, want %q", downstreamBody, body)
	}
}

func TestBodyBufferTooLarge(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for oversized body")
	})

	handler := BodyBuffer(10)(inner) // 10 byte limit
	body := strings.Repeat("x", 11)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestBodyBufferEmpty(t *testing.T) {
	var ctxBody []byte

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxBody = GetBodyBytes(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyBuffer(1024)(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ctxBody != nil {
		t.Errorf("context body = %v, want nil", ctxBody)
	}
}
