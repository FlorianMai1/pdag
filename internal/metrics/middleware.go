package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mai/pdag/internal/middleware"
)

// Middleware instruments HTTP requests with Prometheus metrics.
// It records active requests, request duration, body size, and total request count.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		HTTPActiveRequests.Inc()
		defer HTTPActiveRequests.Dec()

		start := time.Now()
		rec := middleware.NewStatusRecorder(w)

		// Allocate body size pointer so BodyBuffer (downstream) can write to it.
		var bodySize int64
		ctx := middleware.WithBodySizePtr(r.Context(), &bodySize)

		next.ServeHTTP(rec, r.WithContext(ctx))

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", rec.StatusCode)
		pattern := normalizePath(r.URL.Path)

		HTTPRequestsTotal.WithLabelValues(r.Method, pattern, status).Inc()
		HTTPRequestDuration.WithLabelValues(r.Method, pattern, status).Observe(duration)

		if bodySize > 0 {
			HTTPRequestBodyBytes.WithLabelValues(r.Method).Observe(float64(bodySize))
		}
	})
}

// normalizePath groups URL paths to avoid high-cardinality label values.
// PowerDNS API patterns:
//
//	/api/v1/servers/:server_id
//	/api/v1/servers/:server_id/zones
//	/api/v1/servers/:server_id/zones/:zone_id
//	/api/v1/servers/:server_id/zones/:zone_id/...
func normalizePath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// Remove empty trailing parts from trailing slashes.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	// /api/v1/servers/{id}/...
	if len(parts) >= 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "servers" {
		parts[3] = ":server_id"

		// /api/v1/servers/{id}/zones/{zone}/...
		if len(parts) >= 6 && parts[4] == "zones" {
			parts[5] = ":zone_id"
		}
	}

	return "/" + strings.Join(parts, "/")
}
