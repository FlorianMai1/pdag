package audit

import (
	"encoding/json"
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
// When logBody is true, the buffered request body is included in the audit entry.
func Middleware(pub Publisher, logBody bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Allocate the authz result container and place in context
			// so inner middleware (authz) can write to it.
			var authzResult middleware.AuthzResult
			ctx := middleware.WithAuthzResultPtr(r.Context(), &authzResult)

			// Allocate body bytes pointer so BodyBuffer (downstream) can
			// write the buffered request body back to us.
			var bodyBytes []byte
			if logBody {
				ctx = middleware.WithBodyBytesPtr(ctx, &bodyBytes)
			}

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

			if logBody && len(bodyBytes) > 0 {
				// Use json.RawMessage so valid JSON bodies are embedded
				// inline rather than base64-encoded.
				if json.Valid(bodyBytes) {
					entry.RequestBody = json.RawMessage(bodyBytes)
				} else {
					entry.RequestBody = json.RawMessage(`"` + string(bodyBytes) + `"`)
				}
			}

			if err := pub.Publish(entry); err != nil {
				slog.Error("audit log write failed", "request_id", entry.RequestID, "error", err)
				metrics.AuditWriteErrorsTotal.Inc()
			}
		})
	}
}
