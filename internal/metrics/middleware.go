package metrics

import (
	"fmt"
	"net/http"
	"time"

	"github.com/FlorianMai1/pdag/internal/httproute"
	"github.com/FlorianMai1/pdag/internal/middleware"
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
		pattern := httproute.Normalize(r.URL.Path)

		HTTPRequestsTotal.WithLabelValues(r.Method, pattern, status).Inc()
		HTTPRequestDuration.WithLabelValues(r.Method, pattern, status).Observe(duration)

		if bodySize > 0 {
			HTTPRequestBodyBytes.WithLabelValues(r.Method).Observe(float64(bodySize))
		}
	})
}
