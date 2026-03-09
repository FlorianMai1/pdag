package token

import (
	"testing"
	"time"
)

func TestAllowBasic(t *testing.T) {
	l := New(Config{Rate: 10, Burst: 5})

	// First 5 requests should be allowed (burst).
	for i := 0; i < 5; i++ {
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
	for i := 0; i < 5; i++ {
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
	for i := 0; i < 3; i++ {
		l.Allow("cap")
	}

	// Wait long enough to accumulate more than burst tokens.
	time.Sleep(50 * time.Millisecond)

	// Should have refilled to burst (3), not more.
	allowed := 0
	for i := 0; i < 10; i++ {
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
	l.cleanupN = 1 // clean up every call

	l.Allow("stale")

	// Force the bucket to look stale.
	l.mu.Lock()
	l.buckets["stale"].lastCheck = time.Now().Add(-10 * time.Minute)
	l.mu.Unlock()

	// Next call triggers cleanup.
	l.Allow("fresh")

	l.mu.Lock()
	_, staleExists := l.buckets["stale"]
	_, freshExists := l.buckets["fresh"]
	l.mu.Unlock()

	if staleExists {
		t.Error("stale bucket should have been cleaned up")
	}
	if !freshExists {
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
