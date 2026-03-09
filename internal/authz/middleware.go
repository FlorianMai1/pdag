package authz

import (
	"net/http"

	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/sdk"
)

// Middleware returns an HTTP middleware that performs plugin-based authorization.
// It reads the principal's roles from the context (set by authn middleware),
// converts the request to protobuf, and fans out to all assigned plugins.
func Middleware(authz Authorizer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles := middleware.GetRoles(r.Context())
			resultPtr := middleware.GetAuthzResultPtr(r.Context())

			writeResult := func(decision, plugin, reason string) {
				if resultPtr != nil {
					*resultPtr = middleware.AuthzResult{
						Decision: decision,
						Plugin:   plugin,
						Reason:   reason,
					}
				}
			}

			if len(roles) == 0 {
				writeResult("deny", "", "no roles assigned")
				http.Error(w, "Forbidden: no roles assigned", http.StatusForbidden)
				return
			}

			// Build the protobuf request from the HTTP request.
			body := middleware.GetBodyBytes(r.Context())
			reqID := middleware.GetRequestID(r.Context())
			principal := middleware.GetPrincipal(r.Context())
			pbReq := sdk.StdlibToHttpRequest(r, body, reqID, principal)

			// Redact sensitive headers before sending to plugins.
			for i, h := range pbReq.Headers {
				if http.CanonicalHeaderKey(h.Key) == "X-Api-Key" {
					pbReq.Headers[i].Values = []string{"REDACTED"}
				}
			}

			decision, pluginName, reason := authz.Authorize(r.Context(), roles, pbReq)
			writeResult(decision, pluginName, reason)

			if decision != "allow" {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
