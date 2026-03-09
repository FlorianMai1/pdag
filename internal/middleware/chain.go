package middleware

import "net/http"

// Chain composes middlewares so they execute in declaration order.
// The first middleware in the list is the outermost (runs first).
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}
