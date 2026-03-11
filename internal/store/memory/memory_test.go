package memory

import (
	"context"
	"fmt"
	"testing"
	"time"

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

func TestListPaged(t *testing.T) {
	ctx := context.Background()
	s := NewStore()

	// Create 5 keys with staggered CreatedAt for deterministic order.
	for i := 0; i < 5; i++ {
		rec := &store.KeyRecord{
			ID:        fmt.Sprintf("k%d", i),
			Principal: fmt.Sprintf("user%d", i),
			Roles:     []string{"read"},
			Enabled:   true,
			CreatedAt: time.Date(2025, 1, 1, 0, 0, i, 0, time.UTC),
		}
		if err := s.Create(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	// Page 1: limit=2, offset=0 → k0, k1
	page, err := s.ListPaged(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page))
	}
	if page[0].ID != "k0" || page[1].ID != "k1" {
		t.Errorf("page1 = [%s, %s], want [k0, k1]", page[0].ID, page[1].ID)
	}

	// Page 2: limit=2, offset=2 → k2, k3
	page, err = s.ListPaged(ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("page2 len = %d, want 2", len(page))
	}
	if page[0].ID != "k2" || page[1].ID != "k3" {
		t.Errorf("page2 = [%s, %s], want [k2, k3]", page[0].ID, page[1].ID)
	}

	// Page 3: limit=2, offset=4 → k4
	page, err = s.ListPaged(ctx, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 {
		t.Fatalf("page3 len = %d, want 1", len(page))
	}
	if page[0].ID != "k4" {
		t.Errorf("page3 = [%s], want [k4]", page[0].ID)
	}

	// Beyond end: offset=10 → empty
	page, err = s.ListPaged(ctx, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 0 {
		t.Fatalf("beyond end len = %d, want 0", len(page))
	}
}

func TestDeleteExpired(t *testing.T) {
	ctx := context.Background()
	s := NewStore()

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Key with past expiry.
	s.Create(ctx, &store.KeyRecord{
		ID:        "expired1",
		Enabled:   true,
		ExpiresAt: &past,
		CreatedAt: time.Now(),
	})
	// Key with future expiry.
	s.Create(ctx, &store.KeyRecord{
		ID:        "valid1",
		Enabled:   true,
		ExpiresAt: &future,
		CreatedAt: time.Now(),
	})
	// Key with no expiry.
	s.Create(ctx, &store.KeyRecord{
		ID:        "noexpiry1",
		Enabled:   true,
		CreatedAt: time.Now(),
	})
	// Another expired key.
	s.Create(ctx, &store.KeyRecord{
		ID:        "expired2",
		Enabled:   true,
		ExpiresAt: &past,
		CreatedAt: time.Now(),
	})

	n, err := s.DeleteExpired(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// Verify remaining keys.
	list, _ := s.List(ctx)
	if len(list) != 2 {
		t.Fatalf("remaining = %d, want 2", len(list))
	}
	ids := map[string]bool{}
	for _, k := range list {
		ids[k.ID] = true
	}
	if !ids["valid1"] || !ids["noexpiry1"] {
		t.Errorf("unexpected remaining keys: %v", ids)
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
