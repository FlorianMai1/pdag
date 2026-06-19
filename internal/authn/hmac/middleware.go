package hmac

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/mai/pdag/internal/authn"
	"github.com/mai/pdag/internal/clientip"
	"github.com/mai/pdag/internal/metrics"
	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/store"
)

// Middleware returns an HTTP middleware that authenticates requests via the
// X-API-Key header in "keyID:secret" format. The resolver determines the client
// IP used for the per-key allowed_cidrs check (honoring trusted-proxy XFF).
func Middleware(keyStore store.KeyStore, authnService authn.Service, resolver *clientip.Resolver) func(http.Handler) http.Handler {
	tracer := otel.Tracer("pdag.authn")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := middleware.GetRequestID(r.Context())

			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				metrics.AuthnTotal.WithLabelValues("missing_header").Inc()
				slog.Debug("missing X-API-Key header", "request_id", requestID)
				http.Error(w, "missing X-API-Key header", http.StatusUnauthorized)
				return
			}

			keyID, secret, ok := strings.Cut(apiKey, ":")
			if !ok || keyID == "" || secret == "" {
				metrics.AuthnTotal.WithLabelValues("malformed_header").Inc()
				slog.Debug("malformed X-API-Key header", "request_id", requestID)
				http.Error(w, "malformed X-API-Key header", http.StatusUnauthorized)
				return
			}

			// Span covers keystore lookup + HMAC verification.
			parentCtx := r.Context()
			authnCtx, span := tracer.Start(parentCtx, "authn",
				trace.WithAttributes(attribute.String("authn.key_id", keyID)),
			)

			// deny emits an identical generic 401 to the client for every
			// authentication failure (unknown key, bad secret, disabled,
			// expired, IP-not-allowed) so none can be used as a key-state
			// oracle, while keeping the real reason in metrics/span/logs.
			deny := func(label string) {
				metrics.AuthnTotal.WithLabelValues(label).Inc()
				span.SetAttributes(attribute.String("authn.result", label))
				span.End()
				slog.Debug("authentication rejected", "request_id", requestID, "key_id", keyID, "reason", label)
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
			}

			start := time.Now()
			rec, err := keyStore.GetByID(authnCtx, keyID)
			metrics.KeyStoreQueryDuration.Observe(time.Since(start).Seconds())

			if err != nil {
				metrics.KeyStoreErrorsTotal.Inc()
				metrics.AuthnTotal.WithLabelValues("store_error").Inc()
				span.RecordError(err)
				span.SetStatus(codes.Error, "keystore lookup failed")
				span.End()
				slog.Error("keystore lookup failed", "request_id", requestID, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if rec == nil {
				deny("unknown_key")
				return
			}

			// Verify the secret FIRST. Key lifecycle/allowlist state must never
			// be disclosed to a caller who has not proven knowledge of the
			// secret, so every subsequent check returns the same generic 401.
			if err := authnService.Authenticate(secret, rec); err != nil {
				span.RecordError(err)
				if errors.Is(err, authn.ErrInvalidCredentials) {
					deny("invalid_credentials")
				} else {
					// Internal/config error (e.g. unknown hmac_key_id): not a
					// credential guess, surface as 500.
					metrics.AuthnTotal.WithLabelValues("authn_error").Inc()
					span.SetStatus(codes.Error, "authentication failed")
					span.End()
					slog.Error("authentication failed", "request_id", requestID, "key_id", keyID, "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
			}

			if !rec.Enabled {
				deny("disabled")
				return
			}

			if rec.ExpiresAt != nil && rec.ExpiresAt.Before(time.Now()) {
				deny("expired")
				return
			}

			// IP allowlist (defense-in-depth: enforced even with a valid secret).
			if len(rec.AllowedCIDRs) > 0 {
				clientIP := resolver.ClientIP(r)
				if clientIP == nil {
					deny("invalid_source_ip")
					return
				}
				allowed := false
				for _, cidr := range rec.AllowedCIDRs {
					_, ipNet, err := net.ParseCIDR(cidr)
					if err != nil {
						slog.Warn("invalid CIDR in allowlist", "key_id", keyID, "cidr", cidr, "error", err)
						continue
					}
					if ipNet.Contains(clientIP) {
						allowed = true
						break
					}
				}
				if !allowed {
					deny("ip_not_allowed")
					return
				}
			}

			metrics.AuthnTotal.WithLabelValues("success").Inc()
			span.SetAttributes(
				attribute.String("authn.principal", rec.Principal),
				attribute.String("authn.result", "success"),
			)
			span.End()

			// Use parentCtx so downstream spans are siblings, not children of authn.
			ctx := middleware.WithPrincipal(parentCtx, rec.Principal)
			ctx = middleware.WithKeyID(ctx, rec.ID)
			ctx = middleware.WithRoles(ctx, rec.Roles)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
