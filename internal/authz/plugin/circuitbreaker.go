package plugin

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mai/pdag/internal/metrics"
)

// CBState represents the state of a circuit breaker.
type CBState int

const (
	StateClosed   CBState = 0
	StateHalfOpen CBState = 1
	StateOpen     CBState = 2
)

func (s CBState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// CircuitBreaker implements the circuit breaker pattern for a single plugin.
type CircuitBreaker struct {
	mu sync.Mutex

	plugin           string
	failureThreshold int
	successThreshold int
	cooldown         time.Duration

	state                CBState
	consecutiveFailures  int
	consecutiveSuccesses int
	lastFailure          time.Time
	halfOpenAllowed      bool
}

// NewCircuitBreaker creates a circuit breaker for the given plugin.
func NewCircuitBreaker(plugin string, failureThreshold, successThreshold int, cooldown time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		plugin:           plugin,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		cooldown:         cooldown,
		state:            StateClosed,
	}
	metrics.AuthzCircuitBreakerState.WithLabelValues(plugin).Set(float64(StateClosed))
	return cb
}

// Allow checks whether a request should be allowed through.
// Returns true if the call should proceed, false if circuit is open.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.cooldown {
			cb.transition(StateHalfOpen)
			cb.halfOpenAllowed = false // this call is the probe
			return true
		}
		return false
	case StateHalfOpen:
		if cb.halfOpenAllowed {
			cb.halfOpenAllowed = false
			return true
		}
		return false
	}
	return false
}

// RecordSuccess records a successful call.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFailures = 0

	if cb.state == StateHalfOpen {
		cb.consecutiveSuccesses++
		if cb.consecutiveSuccesses >= cb.successThreshold {
			cb.transition(StateClosed)
		} else {
			cb.halfOpenAllowed = true
		}
	}
}

// RecordFailure records a failed call.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveSuccesses = 0
	cb.consecutiveFailures++
	cb.lastFailure = time.Now()

	switch cb.state {
	case StateClosed:
		if cb.consecutiveFailures >= cb.failureThreshold {
			cb.transition(StateOpen)
		}
	case StateHalfOpen:
		cb.transition(StateOpen)
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CBState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *CircuitBreaker) transition(to CBState) {
	from := cb.state
	cb.state = to
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	cb.halfOpenAllowed = (to == StateHalfOpen)

	metrics.AuthzCircuitBreakerState.WithLabelValues(cb.plugin).Set(float64(to))
	metrics.AuthzCircuitBreakerTransitions.WithLabelValues(cb.plugin, from.String(), to.String()).Inc()

	slog.Warn("circuit breaker state change",
		"plugin", cb.plugin,
		"from", from.String(),
		"to", to.String(),
	)
}
