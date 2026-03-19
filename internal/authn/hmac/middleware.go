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
	"github.com/mai/pdag/internal/metrics"
	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/store"
)

// Middleware returns an HTTP middleware that authenticates requests via the
// X-API-Key header in "keyID:secret" format.
func Middleware(keyStore store.KeyStore, authnService authn.Service) func(http.Handler) http.Handler {
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
				metrics.AuthnTotal.WithLabelValues("unknown_key").Inc()
				span.SetAttributes(attribute.String("authn.result", "unknown_key"))
				span.End()
				slog.Debug("unknown key ID", "request_id", requestID, "key_id", keyID)
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}

			// Check IP allowlist before more expensive checks.
			if len(rec.AllowedCIDRs) > 0 {
				sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				clientIP := net.ParseIP(sourceIP)
				if clientIP == nil {
					metrics.AuthnTotal.WithLabelValues("invalid_source_ip").Inc()
					span.SetAttributes(attribute.String("authn.result", "invalid_source_ip"))
					span.End()
					slog.Debug("invalid source IP", "request_id", requestID, "key_id", keyID, "remote_addr", r.RemoteAddr)
					http.Error(w, "invalid source IP", http.StatusForbidden)
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
					metrics.AuthnTotal.WithLabelValues("ip_not_allowed").Inc()
					span.SetAttributes(attribute.String("authn.result", "ip_not_allowed"))
					span.End()
					slog.Debug("IP not in allowlist", "request_id", requestID, "key_id", keyID, "source_ip", sourceIP)
					http.Error(w, "ip not allowed", http.StatusForbidden)
					return
				}
			}

			if !rec.Enabled {
				metrics.AuthnTotal.WithLabelValues("disabled").Inc()
				span.SetAttributes(attribute.String("authn.result", "disabled"))
				span.End()
				slog.Debug("disabled key", "request_id", requestID, "key_id", keyID)
				http.Error(w, "key disabled", http.StatusUnauthorized)
				return
			}

			if rec.ExpiresAt != nil && rec.ExpiresAt.Before(time.Now()) {
				metrics.AuthnTotal.WithLabelValues("expired").Inc()
				span.SetAttributes(attribute.String("authn.result", "expired"))
				span.End()
				slog.Debug("expired key", "request_id", requestID, "key_id", keyID)
				http.Error(w, "key expired", http.StatusUnauthorized)
				return
			}

			if err := authnService.Authenticate(secret, rec); err != nil {
				span.RecordError(err)
				if errors.Is(err, authn.ErrInvalidCredentials) {
					metrics.AuthnTotal.WithLabelValues("invalid_credentials").Inc()
					span.SetAttributes(attribute.String("authn.result", "invalid_credentials"))
					span.End()
					slog.Debug("invalid key secret", "request_id", requestID, "key_id", keyID)
					http.Error(w, "invalid credentials", http.StatusUnauthorized)
				} else {
					metrics.AuthnTotal.WithLabelValues("authn_error").Inc()
					span.SetStatus(codes.Error, "authentication failed")
					span.End()
					slog.Error("authentication failed", "request_id", requestID, "key_id", keyID, "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
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
