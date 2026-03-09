package balancer

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mai/pdag/internal/proxy"
)

var _ proxy.Backend = (*Balancer)(nil)

// Backend describes a single upstream PowerDNS instance.
type Backend struct {
	URL    string
	APIKey string
}

// Config holds the balancer configuration.
type Config struct {
	Backends    []Backend
	HealthCheck HealthCheckConfig
}

// HealthCheckConfig controls active health checking.
type HealthCheckConfig struct {
	Interval time.Duration
	Timeout  time.Duration
	Path     string
}

type backendEntry struct {
	rp      *httputil.ReverseProxy
	url     string
	apiKey  string
	healthy atomic.Bool
}

// Balancer distributes requests across upstream backends using round-robin.
type Balancer struct {
	backends []backendEntry
	counter  atomic.Uint64
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// New creates a round-robin load balancer with active health checking.
func New(cfg Config) (*Balancer, error) {
	if len(cfg.Backends) == 0 {
		return nil, &emptyBackendsError{}
	}

	entries := make([]backendEntry, len(cfg.Backends))
	for i, b := range cfg.Backends {
		target, err := url.Parse(b.URL)
		if err != nil {
			return nil, err
		}

		entry := &entries[i]
		entry.url = b.URL
		entry.apiKey = b.APIKey
		entry.healthy.Store(true)

		apiKey := b.APIKey
		entry.rp = &httputil.ReverseProxy{
			Rewrite: rewriteFunc(target, apiKey),
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				slog.Warn("backend error, marking unhealthy", "backend", entry.url, "error", err)
				entry.healthy.Store(false)
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	lb := &Balancer{
		backends: entries,
		cancel:   cancel,
	}

	lb.wg.Add(1)
	go lb.healthLoop(ctx, cfg.HealthCheck)

	slog.Info("load balancer started", "backends", len(entries))
	return lb, nil
}

// ServeHTTP picks a healthy backend via round-robin and proxies the request.
func (lb *Balancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := uint64(len(lb.backends))
	start := lb.counter.Add(1) - 1

	for i := uint64(0); i < n; i++ {
		idx := (start + i) % n
		if lb.backends[idx].healthy.Load() {
			lb.backends[idx].rp.ServeHTTP(w, r)
			return
		}
	}

	http.Error(w, "no healthy backends", http.StatusBadGateway)
}

// Healthy returns true if at least one backend is available.
func (lb *Balancer) Healthy() bool {
	for i := range lb.backends {
		if lb.backends[i].healthy.Load() {
			return true
		}
	}
	return false
}

// Close stops background health checks and waits for them to finish.
func (lb *Balancer) Close() {
	lb.cancel()
	lb.wg.Wait()
}

// rewriteFunc returns the Rewrite function for a reverse proxy that strips
// client headers and sets the real API key — same logic as proxy.New.
func rewriteFunc(target *url.URL, apiKey string) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		contentType := pr.In.Header.Get("Content-Type")
		contentLength := pr.In.Header.Get("Content-Length")

		for key := range pr.In.Header {
			pr.Out.Header.Del(key)
		}

		pr.Out.Header.Set("X-API-Key", apiKey)
		if contentType != "" {
			pr.Out.Header.Set("Content-Type", contentType)
		}
		if contentLength != "" {
			pr.Out.Header.Set("Content-Length", contentLength)
		}

		pr.SetURL(target)
		pr.Out.Host = target.Host
	}
}

type emptyBackendsError struct{}

func (e *emptyBackendsError) Error() string { return "at least one backend is required" }
