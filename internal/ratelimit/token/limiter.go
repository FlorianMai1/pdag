// Package token provides a per-principal token bucket rate limiter.
package token

import (
	"sync"
	"time"

	"github.com/mai/pdag/internal/ratelimit"
)

// Compile-time interface check.
var _ ratelimit.RateLimiter = (*Limiter)(nil)

const staleThreshold = 5 * time.Minute

// Limiter tracks per-principal token buckets.
// Each bucket has its own mutex so different principals never contend.
type Limiter struct {
	buckets sync.Map // map[string]*bucket
	rate    float64  // tokens per second
	burst   int      // max tokens (bucket capacity)
	stop    chan struct{}
	stopped sync.Once
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

// New creates a new per-principal token bucket rate limiter and starts a
// background goroutine that evicts idle buckets on a fixed cadence (decoupled
// from request volume). Call Close to stop it.
func New(cfg Config) *Limiter {
	l := &Limiter{
		rate:  cfg.Rate,
		burst: cfg.Burst,
		stop:  make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Close stops the background cleanup goroutine. Safe to call more than once.
func (l *Limiter) Close() {
	l.stopped.Do(func() { close(l.stop) })
}

// Allow checks whether the principal is within their rate limit.
// Returns true if the request should proceed, false if rate-limited.
func (l *Limiter) Allow(principal string) bool {
	now := time.Now()

	// Fast path: avoid allocating a bucket on every call for known principals.
	val, ok := l.buckets.Load(principal)
	if !ok {
		val, _ = l.buckets.LoadOrStore(principal, &bucket{
			tokens:    float64(l.burst),
			lastCheck: now,
		})
	}
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

// cleanupLoop periodically evicts idle buckets until Close is called. Running
// on a timer (not per Allow call) decouples eviction from request volume and
// keeps the full-map scan off the hot path.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(staleThreshold / 2)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-ticker.C:
			l.cleanup(now)
		}
	}
}

// cleanup removes buckets idle longer than staleThreshold.
func (l *Limiter) cleanup(now time.Time) {
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
