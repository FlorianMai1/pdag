package audit

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/mai/pdag/internal/clientip"
	"github.com/mai/pdag/internal/metrics"
	"github.com/mai/pdag/internal/middleware"
)

// Options configures the audit middleware.
type Options struct {
	// LogBody embeds the buffered request body in each audit entry.
	LogBody bool
	// FailClosed reserves audit-buffer capacity BEFORE proxying and returns 503
	// if the audit pipeline is saturated, so no audited action is forwarded
	// upstream without a durable slot. Requires the Publisher to implement
	// Reserver (the file logger and Noop do).
	FailClosed bool
	// BodyMaxBytes caps the logged request body (0 = unlimited); larger bodies
	// are truncated with a marker. Only used when LogBody is true.
	BodyMaxBytes int
	// RedactFields is the set of JSON field names (lower-cased) whose values are
	// replaced with a redaction marker before logging. Only used when LogBody.
	RedactFields map[string]bool
}

// Middleware returns an HTTP middleware that logs every request to the audit log
// after the response is written. It reads the status code from the shared context
// pointer set by the metrics middleware (avoiding double StatusRecorder wrapping).
//
// In the default (fail-open) mode the entry is published after the response; a
// saturated buffer drops it (loud metrics). In FailClosed mode a buffer slot is
// reserved before the upstream call and the request is rejected with 503 if the
// audit pipeline is saturated.
func Middleware(pub Publisher, opts Options, resolver *clientip.Resolver) func(http.Handler) http.Handler {
	var reserver Reserver
	if opts.FailClosed {
		r, ok := pub.(Reserver)
		if !ok {
			slog.Error("audit fail-closed mode requires a Reserver publisher; falling back to best-effort publish")
		} else {
			reserver = r
		}
	}

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
			if opts.LogBody {
				ctx = middleware.WithBodyBytesPtr(ctx, &bodyBytes)
			}

			r = r.WithContext(ctx)

			buildEntry := func() Entry {
				statusCode := 0
				if ptr := middleware.GetStatusCodePtr(r.Context()); ptr != nil {
					statusCode = *ptr
				}
				sourceIP := ""
				if ip := resolver.ClientIP(r); ip != nil {
					sourceIP = ip.String()
				}
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
				if opts.LogBody && len(bodyBytes) > 0 {
					// Redact sensitive fields and cap the size before embedding.
					entry.RequestBody = sanitizeBody(bodyBytes, opts.BodyMaxBytes, opts.RedactFields)
				}
				return entry
			}

			if reserver != nil {
				// Fail-closed: reserve a durable slot before the upstream call.
				commit, ok := reserver.Reserve(r.Context())
				if !ok {
					metrics.AuditDroppedTotal.Inc()
					slog.Error("audit pipeline saturated, rejecting request (fail-closed)",
						"request_id", middleware.GetRequestID(ctx))
					http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
					return
				}
				// Guarantee the reserved slot is committed (released) even on a
				// panic in the downstream chain.
				defer func() { commit(buildEntry()) }()
				next.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)

			if err := pub.Publish(buildEntry()); err != nil {
				slog.Error("audit log write failed", "request_id", middleware.GetRequestID(ctx), "error", err)
			}
		})
	}
}
