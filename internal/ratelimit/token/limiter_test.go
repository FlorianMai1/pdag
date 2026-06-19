package token

import (
	"testing"
	"time"
)

func TestAllowBasic(t *testing.T) {
	l := New(Config{Rate: 10, Burst: 5})

	// First 5 requests should be allowed (burst).
	for i := range 5 {
		if !l.Allow("alice") {
			t.Errorf("request %d should be allowed within burst", i+1)
		}
	}

	// 6th request should be denied (burst exhausted, no time to refill).
	if l.Allow("alice") {
		t.Error("request 6 should be denied (burst exhausted)")
	}
}

func TestAllowRefill(t *testing.T) {
	l := New(Config{Rate: 100, Burst: 5})

	// Exhaust burst.
	for range 5 {
		l.Allow("bob")
	}

	if l.Allow("bob") {
		t.Error("should be denied after exhausting burst")
	}

	// Wait for tokens to refill (50ms at 100/s = 5 tokens).
	time.Sleep(60 * time.Millisecond)

	if !l.Allow("bob") {
		t.Error("should be allowed after refill period")
	}
}

func TestAllowPerPrincipal(t *testing.T) {
	l := New(Config{Rate: 10, Burst: 2})

	// Alice uses her burst.
	l.Allow("alice")
	l.Allow("alice")
	if l.Allow("alice") {
		t.Error("alice should be rate limited")
	}

	// Bob should still have his own bucket.
	if !l.Allow("bob") {
		t.Error("bob should not be rate limited by alice's usage")
	}
}

func TestAllowBurstCap(t *testing.T) {
	l := New(Config{Rate: 1000, Burst: 3})

	// Even with high rate, burst caps at 3.
	// Exhaust burst first.
	for range 3 {
		l.Allow("cap")
	}

	// Wait long enough to accumulate more than burst tokens.
	time.Sleep(50 * time.Millisecond)

	// Should have refilled to burst (3), not more.
	allowed := 0
	for range 10 {
		if l.Allow("cap") {
			allowed++
		}
	}
	if allowed > 3 {
		t.Errorf("allowed %d requests, should be capped at burst of 3", allowed)
	}
}

func TestCleanup(t *testing.T) {
	l := New(Config{Rate: 10, Burst: 5})
	defer l.Close()

	l.Allow("stale")
	l.Allow("fresh")

	// Force one bucket to look idle.
	val, _ := l.buckets.Load("stale")
	b := val.(*bucket)
	b.mu.Lock()
	b.lastCheck = time.Now().Add(-10 * time.Minute)
	b.mu.Unlock()

	// Time-based cleanup evicts idle buckets regardless of request volume.
	l.cleanup(time.Now())

	if _, staleExists := l.buckets.Load("stale"); staleExists {
		t.Error("stale bucket should have been cleaned up")
	}
	if _, freshExists := l.buckets.Load("fresh"); !freshExists {
		t.Error("fresh bucket should still exist")
	}
}

func TestZeroConfig(t *testing.T) {
	// Zero rate means no tokens refill — only burst.
	l := New(Config{Rate: 0, Burst: 2})

	if !l.Allow("zero") {
		t.Error("first request should use burst")
	}
	if !l.Allow("zero") {
		t.Error("second request should use burst")
	}
	if l.Allow("zero") {
		t.Error("third request should be denied with zero rate")
	}
}
