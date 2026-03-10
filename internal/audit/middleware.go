package audit

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/mai/pdag/internal/metrics"
	"github.com/mai/pdag/internal/middleware"
)

// Middleware returns an HTTP middleware that logs every request to the audit log
// after the response is written. It reads the status code from the shared context
// pointer set by the metrics middleware (avoiding double StatusRecorder wrapping).
func Middleware(pub Publisher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Allocate the authz result container and place in context
			// so inner middleware (authz) can write to it.
			var authzResult middleware.AuthzResult
			ctx := middleware.WithAuthzResultPtr(r.Context(), &authzResult)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)

			// Read status code from the shared pointer set by the metrics
			// middleware (which owns the single StatusRecorder).
			statusCode := 0
			if ptr := middleware.GetStatusCodePtr(r.Context()); ptr != nil {
				statusCode = *ptr
			}

			sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

			entry := Entry{
				Timestamp:     time.Now().UTC(),
				RequestID:     middleware.GetRequestID(ctx),
				Principal:     middleware.GetPrincipal(ctx),
				KeyID:         middleware.GetKeyID(ctx),
				Method:        r.Method,
				Path:          r.URL.Path,
				Query:         r.URL.RawQuery,
				SourceIP:      sourceIP,
				UserAgent:     r.UserAgent(),
				StatusCode:    statusCode,
				LatencyMs:     time.Since(start).Milliseconds(),
				AuthzDecision: authzResult.Decision,
				AuthzPlugin:   authzResult.Plugin,
				AuthzReason:   authzResult.Reason,
			}

			if err := pub.Publish(entry); err != nil {
				slog.Error("audit log write failed", "request_id", entry.RequestID, "error", err)
				metrics.AuditWriteErrorsTotal.Inc()
			}
		})
	}
}
