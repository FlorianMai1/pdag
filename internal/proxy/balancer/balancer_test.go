package balancer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testBackends(t *testing.T, n int) ([]*httptest.Server, []Backend, []*atomic.Int64) {
	t.Helper()
	servers := make([]*httptest.Server, n)
	backends := make([]Backend, n)
	counts := make([]*atomic.Int64, n)

	for i := range n {
		counts[i] = &atomic.Int64{}
		c := counts[i]
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Add(1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}))
		backends[i] = Backend{URL: servers[i].URL, APIKey: "key-" + servers[i].URL}
	}

	t.Cleanup(func() {
		for _, s := range servers {
			s.Close()
		}
	})

	return servers, backends, counts
}

func newTestBalancer(t *testing.T, backends []Backend) *Balancer {
	t.Helper()
	lb, err := New(Config{
		Backends: backends,
		HealthCheck: HealthCheckConfig{
			Interval: 1 * time.Hour, // don't run during tests
			Timeout:  1 * time.Second,
			Path:     "/",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lb.Close)
	return lb
}

func TestRoundRobin(t *testing.T) {
	_, backends, counts := testBackends(t, 3)
	lb := newTestBalancer(t, backends)

	const total = 90
	for i := range total {
		req := httptest.NewRequest("GET", "/zones", nil)
		rec := httptest.NewRecorder()
		lb.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, rec.Code)
		}
	}

	for i, c := range counts {
		got := c.Load()
		if got != total/3 {
			t.Errorf("backend %d got %d requests, want %d", i, got, total/3)
		}
	}
}

func TestUnhealthyBackendSkipped(t *testing.T) {
	servers, backends, counts := testBackends(t, 3)
	lb := newTestBalancer(t, backends)

	// Mark backend 1 unhealthy.
	servers[1].Close()
	lb.backends[1].healthy.Store(false)

	const total = 20
	for i := range total {
		req := httptest.NewRequest("GET", "/zones", nil)
		rec := httptest.NewRecorder()
		lb.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, rec.Code)
		}
	}

	if counts[1].Load() != 0 {
		t.Errorf("unhealthy backend got %d requests, want 0", counts[1].Load())
	}
	if counts[0].Load() == 0 || counts[2].Load() == 0 {
		t.Error("healthy backends should have received requests")
	}
}

func TestAllUnhealthyReturns502(t *testing.T) {
	_, backends, _ := testBackends(t, 2)
	lb := newTestBalancer(t, backends)

	lb.backends[0].healthy.Store(false)
	lb.backends[1].healthy.Store(false)

	req := httptest.NewRequest("GET", "/zones", nil)
	rec := httptest.NewRecorder()
	lb.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestHealthy(t *testing.T) {
	_, backends, _ := testBackends(t, 2)
	lb := newTestBalancer(t, backends)

	if !lb.Healthy() {
		t.Error("Healthy() = false, want true")
	}

	lb.backends[0].healthy.Store(false)
	if !lb.Healthy() {
		t.Error("Healthy() = false with one backend up, want true")
	}

	lb.backends[1].healthy.Store(false)
	if lb.Healthy() {
		t.Error("Healthy() = true with all backends down, want false")
	}
}

func TestHeaderStripping(t *testing.T) {
	var receivedHeaders http.Header
	var receivedBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	lb := newTestBalancer(t, []Backend{{URL: upstream.URL, APIKey: "real-api-key"}})

	body := `{"zone": "example.com"}`
	req := httptest.NewRequest("PATCH", "/api/v1/servers/localhost/zones/example.com", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "should-be-stripped")
	req.Header.Set("X-Evil-Header", "injected")
	rec := httptest.NewRecorder()

	lb.ServeHTTP(rec, req)

	if got := receivedHeaders.Get("X-API-Key"); got != "real-api-key" {
		t.Errorf("upstream X-API-Key = %q, want %q", got, "real-api-key")
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
	if rec.Header().Get("X-Upstream") != "true" {
		t.Error("upstream response header not proxied")
	}
}

func TestPassiveHealthMarking(t *testing.T) {
	// Start a backend then immediately close it to trigger transport errors.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	lb := newTestBalancer(t, []Backend{{URL: serverURL, APIKey: "key"}})

	req := httptest.NewRequest("GET", "/zones", nil)
	rec := httptest.NewRecorder()
	lb.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if lb.backends[0].healthy.Load() {
		t.Error("backend should be marked unhealthy after transport error")
	}
}

func TestFailoverIdempotentGET(t *testing.T) {
	servers, backends, counts := testBackends(t, 2)
	servers[0].Close() // backend 0 (tried first) is dead

	lb := newTestBalancer(t, backends)

	req := httptest.NewRequest("GET", "/zones", nil)
	rec := httptest.NewRecorder()
	lb.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (should fail over to healthy peer)", rec.Code)
	}
	if got := counts[1].Load(); got != 1 {
		t.Errorf("healthy backend served %d requests, want 1", got)
	}
	if lb.backends[0].healthy.Load() {
		t.Error("dead backend should be marked unhealthy")
	}
}

func TestNoFailoverForNonIdempotent(t *testing.T) {
	servers, backends, counts := testBackends(t, 2)
	servers[0].Close() // backend 0 (tried first) is dead

	lb := newTestBalancer(t, backends)

	req := httptest.NewRequest("PATCH", "/zones", strings.NewReader(`{"rrsets":[]}`))
	rec := httptest.NewRecorder()
	lb.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (PATCH must not fail over)", rec.Code)
	}
	if got := counts[1].Load(); got != 0 {
		t.Errorf("healthy backend served %d requests, want 0 (no retry for PATCH)", got)
	}
}

func TestClientCancelDoesNotMarkUnhealthy(t *testing.T) {
	// Backend blocks until the inbound request is canceled, emulating a client
	// that hangs up mid-request.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	lb := newTestBalancer(t, []Backend{{URL: server.URL, APIKey: "key"}})

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/zones", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	lb.ServeHTTP(rec, req)

	if !lb.backends[0].healthy.Load() {
		t.Error("a client cancellation must NOT mark the backend unhealthy")
	}
}

func TestConcurrentRequests(t *testing.T) {
	_, backends, counts := testBackends(t, 3)
	lb := newTestBalancer(t, backends)

	const goroutines = 10
	const perGoroutine = 30
	var wg sync.WaitGroup

	for range goroutines {
		wg.Go(func() {
			for range perGoroutine {
				req := httptest.NewRequest("GET", "/zones", nil)
				rec := httptest.NewRecorder()
				lb.ServeHTTP(rec, req)
			}
		})
	}

	wg.Wait()

	var total int64
	for _, c := range counts {
		total += c.Load()
	}
	if total != goroutines*perGoroutine {
		t.Errorf("total requests = %d, want %d", total, goroutines*perGoroutine)
	}
}
