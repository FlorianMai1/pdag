// Package ratelimit provides the rate limiting interface and middleware for PDAG.
// The token bucket implementation lives in the ratelimit/token subpackage.
package ratelimit

// RateLimiter decides whether a request from a given principal should be allowed.
type RateLimiter interface {
	Allow(principal string) bool
}

// noop is a RateLimiter that always allows requests.
type noop struct{}

func (noop) Allow(string) bool { return true }

// Noop returns a RateLimiter that allows all requests.
func Noop() RateLimiter { return noop{} }
