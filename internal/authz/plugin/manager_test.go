package plugin

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/mai/pdag/proto/authz"
)

// blockingAuthorizer blocks until the call context is done, then returns the
// context error — emulating a healthy gRPC plugin whose in-flight call ends
// either because a sibling returned ALLOW (parent canceled) or the per-call
// timeout fired.
type blockingAuthorizer struct{}

func (blockingAuthorizer) Authorize(ctx context.Context, _ *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestCallPluginCanceledDoesNotRecordFailure verifies that deliberate
// cancellation (first-ALLOW wins on a sibling) is not counted as a plugin
// failure: the breaker must stay Closed and the decision must be "canceled".
func TestCallPluginCanceledDoesNotRecordFailure(t *testing.T) {
	m := &Manager{}
	m.plugins.Store(&pluginMap{m: make(map[string]*pluginInstance)})

	inst := &pluginInstance{
		authz:   blockingAuthorizer{},
		breaker: NewCircuitBreaker("blocking", 5, 2, 30*time.Second),
		timeout: 5 * time.Second, // generous: cancellation, not timeout, ends the call
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after the call starts (mirrors Authorize's cancel() on first ALLOW).
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	decision, reason := m.callPlugin(ctx, "blocking", inst, &pb.HttpRequest{})

	if decision != "deny" {
		t.Errorf("decision = %q, want deny", decision)
	}
	if !strings.HasPrefix(reason, "canceled:") {
		t.Errorf("reason = %q, want canceled: prefix", reason)
	}
	if got := inst.breaker.State(); got != StateClosed {
		t.Errorf("breaker state = %v, want Closed (cancellation must not record a failure)", got)
	}
}

// TestCallPluginTimeoutRecordsFailure is the control case: a genuine per-call
// timeout (parent ctx NOT canceled) must still record a breaker failure.
func TestCallPluginTimeoutRecordsFailure(t *testing.T) {
	m := &Manager{}
	m.plugins.Store(&pluginMap{m: make(map[string]*pluginInstance)})

	inst := &pluginInstance{
		authz:   blockingAuthorizer{},
		breaker: NewCircuitBreaker("slow", 1, 2, 30*time.Second), // threshold 1 → trips immediately
		timeout: 10 * time.Millisecond,
	}

	decision, reason := m.callPlugin(context.Background(), "slow", inst, &pb.HttpRequest{})
	if decision != "deny" {
		t.Errorf("decision = %q, want deny", decision)
	}
	if !strings.HasPrefix(reason, "timeout:") {
		t.Errorf("reason = %q, want timeout: prefix", reason)
	}
	if got := inst.breaker.State(); got != StateOpen {
		t.Errorf("breaker state = %v, want Open (a real timeout must record a failure)", got)
	}
}
