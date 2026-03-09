package middleware

import (
	"bytes"
	"io"
	"net/http"
)

// BodyBuffer reads the request body into memory (up to maxBytes), stores it in
// context for plugin inspection, and restores r.Body for downstream handlers.
// Returns 413 if the body exceeds maxBytes.
func BodyBuffer(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.Body == http.NoBody {
				ctx := WithBodyBytes(r.Context(), nil)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			limited := io.LimitReader(r.Body, maxBytes+1)
			body, err := io.ReadAll(limited)
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusInternalServerError)
				return
			}
			r.Body.Close()

			if int64(len(body)) > maxBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			ctx := WithBodyBytes(r.Context(), body)
			if sizePtr := GetBodySizePtr(ctx); sizePtr != nil {
				*sizePtr = int64(len(body))
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
