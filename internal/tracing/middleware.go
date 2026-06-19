package tracing

import (
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/FlorianMai1/pdag/internal/httproute"
	"github.com/FlorianMai1/pdag/internal/middleware"
)

// Middleware creates a root span for each HTTP request and extracts incoming
// trace context from headers. When no TracerProvider is configured (tracing
// disabled), all spans are no-ops with zero overhead.
func Middleware(next http.Handler) http.Handler {
	tracer := otel.Tracer("pdag.proxy")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// Use the normalized route template for the span name and http.route to
		// keep trace cardinality bounded; the raw path goes on url.path.
		route := httproute.Normalize(r.URL.Path)
		ctx, span := tracer.Start(ctx, r.Method+" "+route,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("http.route", route),
				attribute.String("url.path", r.URL.Path),
				attribute.String("client.address", r.RemoteAddr),
			),
		)
		defer func() {
			if codePtr := middleware.GetStatusCodePtr(ctx); codePtr != nil {
				span.SetAttributes(attribute.Int("http.response.status_code", *codePtr))
				if *codePtr >= 500 {
					span.SetStatus(codes.Error, http.StatusText(*codePtr))
				}
			}
			span.End()
		}()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
