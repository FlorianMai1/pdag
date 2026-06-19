package postgres_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/mai/pdag/internal/store"
	pgstore "github.com/mai/pdag/internal/store/postgres"
)

// newTestStore spins up a throwaway Postgres container, runs migrations, and
// returns a live store. It skips (not fails) when Docker is unavailable so the
// rest of the suite still runs in constrained environments.
func newTestStore(t *testing.T) *pgstore.Store {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("pdag"),
		tcpostgres.WithUsername("pdag"),
		tcpostgres.WithPassword("pdag-secret"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("skipping postgres integration test (Docker unavailable): %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	migrationsPath, err := filepath.Abs("../../../migrations")
	if err != nil {
		t.Fatal(err)
	}

	s, err := pgstore.NewStore(dsn, migrationsPath)
	if err != nil {
		t.Fatalf("NewStore (migrations should auto-apply): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPostgresStoreCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	rec := &store.KeyRecord{
		ID:           "k_pg",
		KeyHash:      "deadbeef",
		HmacKeyID:    "v1",
		Principal:    "alice",
		Roles:        []string{"admin", "read_zones"},
		AllowedCIDRs: []string{"10.0.0.0/8"},
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := s.Create(ctx, rec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.GetByID(ctx, "k_pg")
	if err != nil || got == nil {
		t.Fatalf("GetByID: %v rec=%v", err, got)
	}
	if got.Principal != "alice" || len(got.Roles) != 2 || len(got.AllowedCIDRs) != 1 {
		t.Errorf("roundtrip mismatch: %+v", got)
	}

	// Mutations.
	if err := s.SetRoles(ctx, "k_pg", []string{"viewer"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
	if err := s.SetEnabled(ctx, "k_pg", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err := s.SetAllowedCIDRs(ctx, "k_pg", []string{"192.168.0.0/16", "203.0.113.0/24"}); err != nil {
		t.Fatalf("SetAllowedCIDRs: %v", err)
	}
	if err := s.UpdateHash(ctx, "k_pg", "cafebabe", "v2"); err != nil {
		t.Fatalf("UpdateHash: %v", err)
	}
	got, _ = s.GetByID(ctx, "k_pg")
	if got.Enabled || len(got.Roles) != 1 || got.Roles[0] != "viewer" ||
		len(got.AllowedCIDRs) != 2 || got.KeyHash != "cafebabe" || got.HmacKeyID != "v2" {
		t.Errorf("post-mutation mismatch: %+v", got)
	}

	// Audit event must persist without error.
	if err := s.AuditKeyEvent(ctx, "k_pg", "update_roles", "test", nil, map[string]any{"roles": []string{"viewer"}}); err != nil {
		t.Errorf("AuditKeyEvent: %v", err)
	}

	// Mutating a missing key surfaces ErrKeyNotFound.
	if err := s.SetEnabled(ctx, "does-not-exist", true); err == nil {
		t.Error("SetEnabled on missing key should error")
	}

	if err := s.Delete(ctx, "k_pg"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, _ := s.GetByID(ctx, "k_pg"); got != nil {
		t.Error("key should be gone after Delete")
	}
}

func TestPostgresStoreNilRolesCoalesced(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Nil Roles must persist as {} (NOT NULL column), not SQL NULL.
	if err := s.Create(ctx, &store.KeyRecord{
		ID: "k_nilroles", KeyHash: "h", HmacKeyID: "v1", Principal: "bob", Roles: nil, Enabled: true,
	}); err != nil {
		t.Fatalf("Create with nil roles: %v", err)
	}
	got, err := s.GetByID(ctx, "k_nilroles")
	if err != nil || got == nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Roles == nil {
		t.Error("nil Roles should round-trip as empty slice, not nil")
	}
}

func TestPostgresStorePagingAndExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i, p := range []string{"u1", "u2", "u3"} {
		if err := s.Create(ctx, &store.KeyRecord{
			ID: "k" + p, KeyHash: "h", HmacKeyID: "v1", Principal: p, Roles: []string{"r"},
			Enabled: true, CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}

	page, err := s.ListPaged(ctx, 2, 0)
	if err != nil || len(page) != 2 {
		t.Fatalf("ListPaged(2,0): len=%d err=%v", len(page), err)
	}
	filtered, err := s.ListFiltered(ctx, 10, 0, "u2", "")
	if err != nil || len(filtered) != 1 || filtered[0].Principal != "u2" {
		t.Fatalf("ListFiltered by principal: %v %v", filtered, err)
	}

	// Expired-key purge.
	past := time.Now().UTC().Add(-time.Hour)
	if err := s.Create(ctx, &store.KeyRecord{
		ID: "k_exp", KeyHash: "h", HmacKeyID: "v1", Principal: "old", Roles: []string{"r"},
		Enabled: true, ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.DeleteExpired(ctx, time.Now().UTC())
	if err != nil || n < 1 {
		t.Errorf("DeleteExpired: n=%d err=%v", n, err)
	}
	if got, _ := s.GetByID(ctx, "k_exp"); got != nil {
		t.Error("expired key should be purged")
	}
}
