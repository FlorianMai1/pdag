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
		// Share the status code with downstream middleware (audit) to avoid double-wrapping.
		ctx = middleware.WithStatusCodePtr(ctx, &rec.StatusCode)

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

// otherPath is the single label value all unrecognized paths fold into, so that
// attacker- or scanner-controlled paths cannot mint unbounded Prometheus series.
const otherPath = "/other"

// knownFixedPaths are non-API endpoints served through this middleware
// (probe chain + metrics) that are safe to keep verbatim.
var knownFixedPaths = map[string]bool{"healthz": true, "readyz": true, "metrics": true}

// zoneTailActions are bounded zone sub-resource verbs kept as literals.
var zoneTailActions = map[string]bool{"export": true, "notify": true, "axfr-retrieve": true, "rectify": true}

// normalizePath maps a request path to a bounded-cardinality label. Known
// PowerDNS templates have their dynamic segments masked (:server_id, :zone_id,
// :cryptokey_id, :kind); every unrecognized path folds into otherPath so the
// label set stays bounded regardless of unauthenticated input.
//
//	/api/v1/servers/:server_id[/zones[/:zone_id[/export|notify|...
//	  |cryptokeys[/:cryptokey_id]|metadata[/:kind]]]]
func normalizePath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// Remove empty trailing parts from trailing slashes.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	if len(parts) == 0 {
		return "/"
	}
	if len(parts) == 1 && knownFixedPaths[parts[0]] {
		return "/" + parts[0]
	}

	// Everything else must be a PowerDNS API path; otherwise fold to /other.
	if !(len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "servers") {
		return otherPath
	}
	if len(parts) == 3 {
		return "/api/v1/servers"
	}

	parts[3] = ":server_id"
	if len(parts) == 4 {
		return "/" + strings.Join(parts, "/")
	}

	// Server-level sub-resource at index 4.
	if parts[4] != "zones" {
		// e.g. config, statistics, search-data — bounded literals. Anything
		// deeper than the sub-resource itself is unexpected → fold.
		if len(parts) == 5 {
			return "/" + strings.Join(parts, "/")
		}
		return otherPath
	}

	if len(parts) == 5 {
		return "/" + strings.Join(parts, "/") // /api/v1/servers/:server_id/zones
	}
	parts[5] = ":zone_id"
	if len(parts) == 6 {
		return "/" + strings.Join(parts, "/") // .../zones/:zone_id
	}

	// Zone sub-resource tail at index 6 (and optional ID at index 7).
	switch tail := parts[6]; {
	case zoneTailActions[tail] && len(parts) == 7:
		return "/" + strings.Join(parts, "/")
	case tail == "cryptokeys":
		if len(parts) == 7 {
			return "/" + strings.Join(parts, "/")
		}
		if len(parts) == 8 {
			parts[7] = ":cryptokey_id"
			return "/" + strings.Join(parts, "/")
		}
		return otherPath
	case tail == "metadata":
		if len(parts) == 7 {
			return "/" + strings.Join(parts, "/")
		}
		if len(parts) == 8 {
			parts[7] = ":kind"
			return "/" + strings.Join(parts, "/")
		}
		return otherPath
	default:
		return otherPath
	}
}
