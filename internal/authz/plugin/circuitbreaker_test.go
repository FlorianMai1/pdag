package plugin

import (
	"testing"
	"time"
)

func TestCircuitBreakerStartsClosed(t *testing.T) {
	cb := NewCircuitBreaker("test", 3, 2, 5*time.Second)
	if cb.State() != StateClosed {
		t.Errorf("initial state = %v, want Closed", cb.State())
	}
	if !cb.Allow() {
		t.Error("closed breaker should allow")
	}
}

func TestCircuitBreakerTripsOpen(t *testing.T) {
	cb := NewCircuitBreaker("test", 3, 2, 5*time.Second)

	// 3 consecutive failures should trip to open.
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != StateOpen {
		t.Errorf("state = %v, want Open", cb.State())
	}
	if cb.Allow() {
		t.Error("open breaker should not allow")
	}
}

func TestCircuitBreakerHalfOpenAfterCooldown(t *testing.T) {
	cb := NewCircuitBreaker("test", 2, 1, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("state = %v, want Open", cb.State())
	}

	// Wait for cooldown.
	time.Sleep(15 * time.Millisecond)

	if !cb.Allow() {
		t.Error("should allow after cooldown (probe)")
	}
	if cb.State() != StateHalfOpen {
		t.Errorf("state = %v, want HalfOpen", cb.State())
	}
}

func TestCircuitBreakerClosesOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker("test", 2, 2, 10*time.Millisecond)

	// Trip open.
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for cooldown → half-open.
	time.Sleep(15 * time.Millisecond)
	cb.Allow()

	// 2 successes in half-open → closed.
	cb.RecordSuccess()
	cb.RecordSuccess()

	if cb.State() != StateClosed {
		t.Errorf("state = %v, want Closed", cb.State())
	}
}

func TestCircuitBreakerReopensOnFailureInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker("test", 2, 2, 10*time.Millisecond)

	// Trip open.
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for cooldown → half-open.
	time.Sleep(15 * time.Millisecond)
	cb.Allow()

	// Failure in half-open → back to open.
	cb.RecordFailure()

	if cb.State() != StateOpen {
		t.Errorf("state = %v, want Open", cb.State())
	}
}

func TestCircuitBreakerSuccessResetsClosed(t *testing.T) {
	cb := NewCircuitBreaker("test", 3, 2, 5*time.Second)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // Resets consecutive failures.
	cb.RecordFailure()
	cb.RecordFailure()

	// Only 2 consecutive failures, not 3 — should still be closed.
	if cb.State() != StateClosed {
		t.Errorf("state = %v, want Closed", cb.State())
	}
}
