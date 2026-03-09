package proxy

import "net/http"

// Backend selects a healthy upstream and proxies the request.
type Backend interface {
	http.Handler
	// Healthy returns true if at least one upstream backend is available.
	Healthy() bool
	// Close stops background health checks and releases resources.
	Close()
}
