package hmac

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mai/pdag/internal/authn"
	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/store"
)

// Middleware returns an HTTP middleware that authenticates requests via the
// X-API-Key header in "keyID:secret" format.
func Middleware(keyStore store.KeyStore, authnService authn.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := middleware.GetRequestID(r.Context())

			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				slog.Debug("missing X-API-Key header", "request_id", requestID)
				http.Error(w, "missing X-API-Key header", http.StatusUnauthorized)
				return
			}

			keyID, secret, ok := strings.Cut(apiKey, ":")
			if !ok || keyID == "" || secret == "" {
				slog.Debug("malformed X-API-Key header", "request_id", requestID)
				http.Error(w, "malformed X-API-Key header", http.StatusUnauthorized)
				return
			}

			rec, err := keyStore.GetByID(r.Context(), keyID)
			if err != nil {
				slog.Error("keystore lookup failed", "request_id", requestID, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if rec == nil {
				slog.Debug("unknown key ID", "request_id", requestID, "key_id", keyID)
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}

			if !rec.Enabled {
				slog.Debug("disabled key", "request_id", requestID, "key_id", keyID)
				http.Error(w, "key disabled", http.StatusUnauthorized)
				return
			}

			if rec.ExpiresAt != nil && rec.ExpiresAt.Before(time.Now()) {
				slog.Debug("expired key", "request_id", requestID, "key_id", keyID)
				http.Error(w, "key expired", http.StatusUnauthorized)
				return
			}

			if err := authnService.Authenticate(secret, rec); err != nil {
				if errors.Is(err, authn.ErrInvalidCredentials) {
					slog.Debug("invalid key secret", "request_id", requestID, "key_id", keyID)
					http.Error(w, "invalid credentials", http.StatusUnauthorized)
				} else {
					slog.Error("authentication failed", "request_id", requestID, "key_id", keyID, "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
			}

			ctx := r.Context()
			ctx = middleware.WithPrincipal(ctx, rec.Principal)
			ctx = middleware.WithKeyID(ctx, rec.ID)
			ctx = middleware.WithRoles(ctx, rec.Roles)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
