package middleware

import (
	"context"
	"testing"
)

func TestAuthzResultPtr(t *testing.T) {
	ctx := context.Background()

	// No pointer set — returns nil.
	if ptr := GetAuthzResultPtr(ctx); ptr != nil {
		t.Fatal("expected nil pointer from empty context")
	}

	// GetAuthzResult returns false when no pointer.
	if _, ok := GetAuthzResult(ctx); ok {
		t.Fatal("expected ok=false from empty context")
	}

	// Allocate and set a pointer.
	result := &AuthzResult{}
	ctx = WithAuthzResultPtr(ctx, result)

	// Retrieve the pointer and write to it.
	ptr := GetAuthzResultPtr(ctx)
	if ptr == nil {
		t.Fatal("expected non-nil pointer")
		return
	}
	ptr.Decision = "allow"
	ptr.Plugin = "admin"
	ptr.Reason = "full access"

	// GetAuthzResult should see the written values.
	got, ok := GetAuthzResult(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Decision != "allow" || got.Plugin != "admin" || got.Reason != "full access" {
		t.Errorf("got %+v, want {allow admin full access}", got)
	}
}

func TestAuthzResultPtrSharedWrite(t *testing.T) {
	// Simulates audit middleware allocating, authz middleware writing.
	result := &AuthzResult{}
	ctx := WithAuthzResultPtr(context.Background(), result)

	// "authz middleware" writes via pointer from context.
	ptr := GetAuthzResultPtr(ctx)
	*ptr = AuthzResult{Decision: "deny", Plugin: "read_zones", Reason: "method not allowed"}

	// "audit middleware" reads the original pointer.
	if result.Decision != "deny" {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
	if result.Plugin != "read_zones" {
		t.Errorf("plugin = %q, want read_zones", result.Plugin)
	}
}
