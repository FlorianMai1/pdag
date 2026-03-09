package memory

import (
	"context"
	"testing"

	"github.com/mai/pdag/internal/store"
)

func TestStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := NewStore()

	// Create
	rec := &store.KeyRecord{
		ID:        "k1",
		KeyHash:   "hash1",
		HmacKeyID: "v1",
		Principal: "alice",
		Roles:     []string{"admin"},
		Enabled:   true,
	}
	if err := s.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// Duplicate create should fail.
	if err := s.Create(ctx, rec); err == nil {
		t.Fatal("expected error on duplicate create")
	}

	// GetByID
	got, err := s.GetByID(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected record, got nil")
	}
	if got.Principal != "alice" {
		t.Errorf("principal = %q, want %q", got.Principal, "alice")
	}
	if len(got.Roles) != 1 || got.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", got.Roles)
	}

	// GetByID returns nil for missing key.
	missing, err := s.GetByID(ctx, "nope")
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Errorf("expected nil for missing key, got %+v", missing)
	}

	// List
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("list len = %d, want 1", len(list))
	}

	// SetEnabled
	if err := s.SetEnabled(ctx, "k1", false); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetByID(ctx, "k1")
	if got.Enabled {
		t.Error("expected disabled")
	}

	// SetRoles
	if err := s.SetRoles(ctx, "k1", []string{"read_zones", "zone-admin"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetByID(ctx, "k1")
	if len(got.Roles) != 2 {
		t.Errorf("roles = %v, want [read_zones zone-admin]", got.Roles)
	}

	// UpdateHash
	if err := s.UpdateHash(ctx, "k1", "newhash", "v2"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetByID(ctx, "k1")
	if got.KeyHash != "newhash" || got.HmacKeyID != "v2" {
		t.Errorf("hash = %q/%q, want newhash/v2", got.KeyHash, got.HmacKeyID)
	}

	// Delete
	if err := s.Delete(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetByID(ctx, "k1")
	if got != nil {
		t.Error("expected nil after delete")
	}

	// Delete missing should error.
	if err := s.Delete(ctx, "k1"); err == nil {
		t.Fatal("expected error deleting missing key")
	}
}

func TestStoreReturnsCopies(t *testing.T) {
	ctx := context.Background()
	s := NewStore()

	rec := &store.KeyRecord{
		ID:      "k1",
		Roles:   []string{"admin"},
		Enabled: true,
	}
	s.Create(ctx, rec)

	// Mutating the input should not affect the store.
	rec.Roles[0] = "mutated"

	got, _ := s.GetByID(ctx, "k1")
	if got.Roles[0] != "admin" {
		t.Errorf("store was mutated via input: roles[0] = %q", got.Roles[0])
	}

	// Mutating the output should not affect the store.
	got.Roles[0] = "mutated"
	got2, _ := s.GetByID(ctx, "k1")
	if got2.Roles[0] != "admin" {
		t.Errorf("store was mutated via output: roles[0] = %q", got2.Roles[0])
	}
}
