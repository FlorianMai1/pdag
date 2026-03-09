package single

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/mai/pdag/internal/proxy"
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
