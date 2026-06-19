package balancer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/proxy"
)

var _ proxy.Backend = (*Balancer)(nil)

// maxAttempts bounds how many backends a single request may be tried against
// (the chosen backend plus at most one failover), so a request never fans out
// across the whole pool when backends are failing.
const maxAttempts = 2

// attemptState carries the outcome of one ReverseProxy attempt back to
// ServeHTTP via the request context, so the balancer (not the ReverseProxy)
// decides whether to retry or commit a 502.
type attemptState struct {
	failed   bool // transport error occurred (no response committed to the client)
	canceled bool // the inbound client canceled — not a backend health signal
}

type attemptCtxKey struct{}

// isIdempotentMethod reports whether a failed request may be safely replayed
// against another backend.
func isIdempotentMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

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
				st, _ := r.Context().Value(attemptCtxKey{}).(*attemptState)

				// A client-side cancellation says nothing about backend health
				// and must not be retried or 502'd — the client is already gone.
				if errors.Is(err, context.Canceled) || r.Context().Err() != nil {
					slog.Debug("backend request canceled by client", "backend", entry.url)
					if st != nil {
						st.failed = true
						st.canceled = true
					}
					return
				}

				slog.Warn("backend error, marking unhealthy", "backend", entry.url, "error", err)
				entry.healthy.Store(false)
				if st != nil {
					// Let ServeHTTP decide whether to fail over or write 502.
					// Nothing is written here, so the response is still pristine
					// (ErrorHandler only fires on pre-response transport errors).
					st.failed = true
					return
				}
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

// ServeHTTP picks a healthy backend via round-robin and proxies the request,
// with bounded request-level failover: on a transport error (not a client
// cancellation) for an idempotent method, it retries one other healthy backend
// before giving up with a 502. At most maxAttempts backends are tried.
func (lb *Balancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := uint64(len(lb.backends))
	start := lb.counter.Add(1) - 1

	// Buffered request body (set by the BodyBuffer middleware) so a retry can
	// replay it; nil for bodyless requests.
	body := middleware.GetBodyBytes(r.Context())

	attempts := 0
	for i := uint64(0); i < n && attempts < maxAttempts; i++ {
		idx := (start + i) % n
		if !lb.backends[idx].healthy.Load() {
			continue
		}

		if body != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		st := &attemptState{}
		ar := r.WithContext(context.WithValue(r.Context(), attemptCtxKey{}, st))
		lb.backends[idx].rp.ServeHTTP(w, ar)
		attempts++

		if !st.failed {
			return // backend committed a response
		}
		if st.canceled {
			return // client disconnected; nothing to retry or write
		}
		if !isIdempotentMethod(r.Method) {
			break // do not replay a non-idempotent request
		}
	}

	if attempts == 0 {
		http.Error(w, "no healthy backends", http.StatusBadGateway)
		return
	}
	http.Error(w, "bad gateway", http.StatusBadGateway)
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
		accept := pr.In.Header.Get("Accept")

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
		if accept != "" {
			pr.Out.Header.Set("Accept", accept)
		}

		pr.SetURL(target)
		pr.Out.Host = target.Host
	}
}

type emptyBackendsError struct{}

func (e *emptyBackendsError) Error() string { return "at least one backend is required" }
