// Package token provides a per-principal token bucket rate limiter.
package token

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mai/pdag/internal/ratelimit"
)

// Compile-time interface check.
var _ ratelimit.RateLimiter = (*Limiter)(nil)

// Limiter tracks per-principal token buckets.
// Each bucket has its own mutex so different principals never contend.
type Limiter struct {
	buckets  sync.Map     // map[string]*bucket
	rate     float64      // tokens per second
	burst    int          // max tokens (bucket capacity)
	cleanupN int64        // clean up every N calls to Allow
	calls    atomic.Int64 // total Allow calls (lock-free counter)
}

type bucket struct {
	mu        sync.Mutex
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
		rate:     cfg.Rate,
		burst:    cfg.Burst,
		cleanupN: 1000,
	}
}

// Allow checks whether the principal is within their rate limit.
// Returns true if the request should proceed, false if rate-limited.
func (l *Limiter) Allow(principal string) bool {
	now := time.Now()

	n := l.calls.Add(1)
	if n%l.cleanupN == 0 {
		l.cleanup(now)
	}

	newBucket := &bucket{
		tokens:    float64(l.burst),
		lastCheck: now,
	}
	val, _ := l.buckets.LoadOrStore(principal, newBucket)
	b := val.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()

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

// cleanup removes stale buckets that have been idle for a while.
func (l *Limiter) cleanup(now time.Time) {
	staleThreshold := 5 * time.Minute
	l.buckets.Range(func(key, val any) bool {
		b := val.(*bucket)
		b.mu.Lock()
		stale := now.Sub(b.lastCheck) > staleThreshold
		b.mu.Unlock()
		if stale {
			l.buckets.Delete(key)
		}
		return true
	})
}
