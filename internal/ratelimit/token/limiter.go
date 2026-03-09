// Package token provides a per-principal token bucket rate limiter.
package token

import (
	"sync"
	"time"

	"github.com/mai/pdag/internal/ratelimit"
)

// Compile-time interface check.
var _ ratelimit.RateLimiter = (*Limiter)(nil)

// Limiter tracks per-principal token buckets.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    int     // max tokens (bucket capacity)
	cleanupN int     // clean up every N calls to Allow
	calls    int
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// Config holds token bucket rate limiter configuration.
type Config struct {
	Rate  float64 // requests per second per principal
	Burst int     // maximum burst size per principal
}

// New creates a new per-principal token bucket rate limiter.
func New(cfg Config) *Limiter {
	return &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     cfg.Rate,
		burst:    cfg.Burst,
		cleanupN: 1000,
	}
}

// Allow checks whether the principal is within their rate limit.
// Returns true if the request should proceed, false if rate-limited.
func (l *Limiter) Allow(principal string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%l.cleanupN == 0 {
		l.cleanup(now)
	}

	b, ok := l.buckets[principal]
	if !ok {
		b = &bucket{
			tokens:    float64(l.burst) - 1, // consume one token
			lastCheck: now,
		}
		l.buckets[principal] = b
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastCheck = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// cleanup removes stale buckets that have been full for a while.
func (l *Limiter) cleanup(now time.Time) {
	staleThreshold := 5 * time.Minute
	for k, b := range l.buckets {
		if now.Sub(b.lastCheck) > staleThreshold {
			delete(l.buckets, k)
		}
	}
}
