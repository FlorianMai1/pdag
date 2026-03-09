package middleware

import (
	"net/http"
	"testing"
)

func TestSanitizeHeaders(t *testing.T) {
	h := http.Header{
		"Content-Type": {"application/json"},
		"X-Api-Key":    {"secret:value"},
		"X-Custom":     {"safe"},
	}

	sanitized := SanitizeHeaders(h)

	if sanitized.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type was modified")
	}
	if sanitized.Get("X-Api-Key") != "REDACTED" {
		t.Errorf("X-Api-Key = %q, want REDACTED", sanitized.Get("X-Api-Key"))
	}
	if sanitized.Get("X-Custom") != "safe" {
		t.Errorf("X-Custom was modified")
	}

	// Original should not be mutated.
	if h.Get("X-Api-Key") != "secret:value" {
		t.Errorf("original header was mutated")
	}
}
