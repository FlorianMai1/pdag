package single

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/FlorianMai1/pdag/internal/metrics"
	"github.com/FlorianMai1/pdag/internal/proxy"
)

var _ proxy.Backend = (*Backend)(nil)

// Backend is a proxy.Backend backed by a single upstream reverse proxy.
// It is always considered healthy and Close is a no-op.
type Backend struct {
	rp *httputil.ReverseProxy
}

// New creates a single-backend proxy that forwards requests to the upstream
// PowerDNS API. It strips all client-supplied headers and sets only X-API-Key,
// Host, Content-Type, and Content-Length on the outbound request.
func New(upstreamURL string, apiKey string) (*Backend, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			contentType := pr.In.Header.Get("Content-Type")
			accept := pr.In.Header.Get("Accept")

			for key := range pr.In.Header {
				pr.Out.Header.Del(key)
			}

			pr.Out.Header.Set("X-API-Key", apiKey)
			if contentType != "" {
				pr.Out.Header.Set("Content-Type", contentType)
			}
			if accept != "" {
				pr.Out.Header.Set("Accept", accept)
			}
			// Content-Length is carried by pr.Out and set by the transport.

			pr.SetURL(target)
			pr.Out.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A client-side cancellation is not an upstream failure.
			if errors.Is(err, context.Canceled) || r.Context().Err() != nil {
				slog.Debug("upstream request canceled by client", "error", err)
				return
			}
			slog.Warn("upstream request failed", "error", err)
			metrics.UpstreamErrorsTotal.WithLabelValues("transport").Inc()
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	return &Backend{rp: rp}, nil
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.rp.ServeHTTP(w, r)
}

// Healthy always returns true for a single backend.
func (b *Backend) Healthy() bool { return true }

// Close is a no-op for a single backend.
func (b *Backend) Close() {}
