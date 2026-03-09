package single

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeaderRewriting(t *testing.T) {
	var receivedHeaders http.Header
	var receivedBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	b, err := New(upstream.URL, "real-api-key")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"zone": "example.com"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/example.com", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "should-be-stripped")
	req.Header.Set("X-Evil-Header", "injected")
	rec := httptest.NewRecorder()

	b.ServeHTTP(rec, req)

	if got := receivedHeaders.Get("X-API-Key"); got != "real-api-key" {
		t.Errorf("upstream X-API-Key = %q, want %q", got, "real-api-key")
	}
	if got := receivedHeaders.Get("X-Api-Key"); got == "should-be-stripped" {
		t.Error("client X-Api-Key was not stripped")
	}
	if got := receivedHeaders.Get("X-Evil-Header"); got != "" {
		t.Errorf("X-Evil-Header = %q, should have been stripped", got)
	}
	if got := receivedHeaders.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if receivedBody != body {
		t.Errorf("upstream body = %q, want %q", receivedBody, body)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("response status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Upstream") != "true" {
		t.Error("upstream response header not proxied")
	}
}

func TestAlwaysHealthy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b, err := New(upstream.URL, "key")
	if err != nil {
		t.Fatal(err)
	}

	if !b.Healthy() {
		t.Error("Healthy() = false, want true")
	}

	b.Close()
}
