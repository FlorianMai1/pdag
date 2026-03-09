package ratelimit

import (
	"net/http"

	"github.com/mai/pdag/internal/metrics"
	"github.com/mai/pdag/internal/middleware"
)

// Middleware returns an HTTP middleware that rate-limits requests per principal.
// It must be placed after authentication middleware (which sets the principal in context).
// Returns 429 Too Many Requests when the rate limit is exceeded.
func Middleware(limiter RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := middleware.GetPrincipal(r.Context())
			if principal == "" {
				// No principal means unauthenticated — authn middleware should
				// have rejected already, but don't rate-limit unknown callers.
				next.ServeHTTP(w, r)
				return
			}

			if !limiter.Allow(principal) {
				metrics.RateLimitedTotal.WithLabelValues(principal).Inc()
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
