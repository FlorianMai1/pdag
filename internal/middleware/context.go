package middleware

import (
	"context"
	"net/http"
)

type contextKey string

const (
	requestIDKey   contextKey = "requestID"
	principalKey   contextKey = "principal"
	keyIDKey       contextKey = "keyID"
	rolesKey       contextKey = "roles"
	bodyBytesKey   contextKey = "bodyBytes"
	bodySizePtrKey contextKey = "bodySizePtr"
	authzResultKey contextKey = "authzResult"
	statusCodeKey  contextKey = "statusCodePtr"
)

type AuthzResult struct {
	Decision string // "allow", "deny"
	Plugin   string
	Reason   string
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func GetRequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

func WithPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

func GetPrincipal(ctx context.Context) string {
	v, _ := ctx.Value(principalKey).(string)
	return v
}

func WithKeyID(ctx context.Context, keyID string) context.Context {
	return context.WithValue(ctx, keyIDKey, keyID)
}

func GetKeyID(ctx context.Context) string {
	v, _ := ctx.Value(keyIDKey).(string)
	return v
}

func WithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, rolesKey, roles)
}

func GetRoles(ctx context.Context) []string {
	v, _ := ctx.Value(rolesKey).([]string)
	return v
}

func WithBodyBytes(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, bodyBytesKey, body)
}

func GetBodyBytes(ctx context.Context) []byte {
	v, _ := ctx.Value(bodyBytesKey).([]byte)
	return v
}

// WithBodySizePtr stores a pointer that downstream middleware can write body size to.
func WithBodySizePtr(ctx context.Context, size *int64) context.Context {
	return context.WithValue(ctx, bodySizePtrKey, size)
}

// GetBodySizePtr retrieves the body size pointer from context.
func GetBodySizePtr(ctx context.Context) *int64 {
	v, _ := ctx.Value(bodySizePtrKey).(*int64)
	return v
}

func GetAuthzResult(ctx context.Context) (AuthzResult, bool) {
	if ptr := GetAuthzResultPtr(ctx); ptr != nil {
		return *ptr, true
	}
	return AuthzResult{}, false
}

// WithAuthzResultPtr stores an AuthzResult pointer in context.
// The audit middleware allocates the pointer; the authz middleware writes to it.
func WithAuthzResultPtr(ctx context.Context, result *AuthzResult) context.Context {
	return context.WithValue(ctx, authzResultKey, result)
}

// GetAuthzResultPtr retrieves the AuthzResult pointer from context.
func GetAuthzResultPtr(ctx context.Context) *AuthzResult {
	v, _ := ctx.Value(authzResultKey).(*AuthzResult)
	return v
}

// WithStatusCodePtr stores a pointer to a status code int in context.
// The metrics middleware allocates the pointer; the audit middleware reads it.
func WithStatusCodePtr(ctx context.Context, code *int) context.Context {
	return context.WithValue(ctx, statusCodeKey, code)
}

// GetStatusCodePtr retrieves the status code pointer from context.
func GetStatusCodePtr(ctx context.Context) *int {
	v, _ := ctx.Value(statusCodeKey).(*int)
	return v
}

// SanitizeHeaders returns a copy of the headers with X-Api-Key values redacted.
func SanitizeHeaders(h http.Header) http.Header {
	sanitized := make(http.Header, len(h))
	for key, values := range h {
		sanitized[key] = make([]string, len(values))
		copy(sanitized[key], values)
		if http.CanonicalHeaderKey(key) == "X-Api-Key" {
			for i := range sanitized[key] {
				sanitized[key][i] = "REDACTED"
			}
		}
	}
	return sanitized
}
