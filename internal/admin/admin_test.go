package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FlorianMai1/pdag/internal/admin"
	adminhmac "github.com/FlorianMai1/pdag/internal/admin/hmac"
	"github.com/FlorianMai1/pdag/internal/store"
	"github.com/FlorianMai1/pdag/internal/store/memory"
)

var (
	testKeygen = adminhmac.NewGenerator("v1", "test-secret")
	testToken  = "test-token"
)

func TestCreateAndListKeys(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create a key.
	body := `{"principal":"alice","roles":["admin","read_zones"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var created struct {
		ID        string   `json:"id"`
		Secret    string   `json:"secret"`
		Principal string   `json:"principal"`
		Roles     []string `json:"roles"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Principal != "alice" {
		t.Errorf("principal = %q, want alice", created.Principal)
	}
	if created.ID == "" || created.Secret == "" {
		t.Error("id or secret is empty")
	}

	// List keys.
	req = httptest.NewRequest("GET", "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", rec.Code, http.StatusOK)
	}

	var keys []struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].ID != created.ID {
		t.Errorf("id = %q, want %q", keys[0].ID, created.ID)
	}
}

func TestAuthRequired(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// No token.
	req := httptest.NewRequest("GET", "/admin/keys", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Wrong token.
	req = httptest.NewRequest("GET", "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDisableEnableDelete(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create a key first.
	body := `{"principal":"bob","roles":["read_zones"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Disable.
	req = httptest.NewRequest("PATCH", "/admin/keys/"+created.ID+"/disable", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("disable status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Verify disabled.
	k, _ := mgr.GetByID(req.Context(), created.ID)
	if k.Enabled {
		t.Error("key should be disabled")
	}

	// Enable.
	req = httptest.NewRequest("PATCH", "/admin/keys/"+created.ID+"/enable", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("enable status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/admin/keys/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Verify deleted.
	k, _ = mgr.GetByID(req.Context(), created.ID)
	if k != nil {
		t.Error("key should be deleted")
	}
}

func TestUpdateRoles(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create.
	body := `{"principal":"carol","roles":["read_zones"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Update roles.
	rolesBody := `{"roles":["admin","read_zones"]}`
	req = httptest.NewRequest("PUT", "/admin/keys/"+created.ID+"/roles", bytes.NewBufferString(rolesBody))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("update roles status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	k, _ := mgr.GetByID(req.Context(), created.ID)
	if len(k.Roles) != 2 || k.Roles[0] != "admin" || k.Roles[1] != "read_zones" {
		t.Errorf("roles = %v, want [admin read_zones]", k.Roles)
	}
}

func TestListKeysPagination(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create 5 keys.
	for i := range 5 {
		body := fmt.Sprintf(`{"principal":"user%d","roles":["read"]}`, i)
		req := httptest.NewRequest("POST", "/admin/keys", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: status = %d", i, rec.Code)
		}
	}

	// Default (no params) returns all 5.
	req := httptest.NewRequest("GET", "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var keys []json.RawMessage
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 5 {
		t.Fatalf("default: got %d keys, want 5", len(keys))
	}

	// limit=2 returns 2.
	req = httptest.NewRequest("GET", "/admin/keys?limit=2", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 2 {
		t.Fatalf("limit=2: got %d keys, want 2", len(keys))
	}

	// limit=2&offset=3 returns 2.
	req = httptest.NewRequest("GET", "/admin/keys?limit=2&offset=3", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 2 {
		t.Fatalf("limit=2&offset=3: got %d keys, want 2", len(keys))
	}

	// offset=10 returns 0.
	req = httptest.NewRequest("GET", "/admin/keys?offset=10", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 0 {
		t.Fatalf("offset=10: got %d keys, want 0", len(keys))
	}
}

func TestListKeysFiltering(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create keys with different principals and roles directly in store.
	now := time.Now()
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_alice1", Principal: "alice", Roles: []string{"admin", "read_zones"},
		Enabled: true, CreatedAt: now,
	})
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_alice2", Principal: "alice", Roles: []string{"read_zones"},
		Enabled: true, CreatedAt: now.Add(time.Second),
	})
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_bob1", Principal: "bob", Roles: []string{"admin"},
		Enabled: true, CreatedAt: now.Add(2 * time.Second),
	})

	// Filter by principal.
	req := httptest.NewRequest("GET", "/admin/keys?principal=alice", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var keys []struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 2 {
		t.Fatalf("principal=alice: got %d keys, want 2", len(keys))
	}

	// Filter by role.
	req = httptest.NewRequest("GET", "/admin/keys?role=admin", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 2 {
		t.Fatalf("role=admin: got %d keys, want 2", len(keys))
	}

	// Filter by both.
	req = httptest.NewRequest("GET", "/admin/keys?principal=alice&role=admin", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 1 {
		t.Fatalf("principal=alice&role=admin: got %d keys, want 1", len(keys))
	}
	if keys[0].ID != "k_alice1" {
		t.Errorf("expected k_alice1, got %s", keys[0].ID)
	}
}

func TestRotateKey(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create a key.
	body := `{"principal":"alice","roles":["admin"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Get original hash.
	origKey, _ := mgr.GetByID(context.Background(), created.ID)
	origHash := origKey.KeyHash

	// Rotate.
	req = httptest.NewRequest("POST", "/admin/keys/"+created.ID+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var rotated struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &rotated)

	if rotated.ID != created.ID {
		t.Errorf("rotated id = %q, want %q", rotated.ID, created.ID)
	}
	if rotated.Secret == "" {
		t.Error("rotated secret is empty")
	}
	if rotated.Secret == created.Secret {
		t.Error("rotated secret should differ from original")
	}

	// Verify hash was updated in store.
	updatedKey, _ := mgr.GetByID(context.Background(), created.ID)
	if updatedKey.KeyHash == origHash {
		t.Error("key hash should have changed after rotation")
	}

	// Principal and roles should be unchanged.
	if updatedKey.Principal != "alice" {
		t.Errorf("principal = %q, want alice", updatedKey.Principal)
	}
	if len(updatedKey.Roles) != 1 || updatedKey.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", updatedKey.Roles)
	}
}

func TestRotateKeyNotFound(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	req := httptest.NewRequest("POST", "/admin/keys/nonexistent/rotate", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("rotate missing key: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestPurgeExpiredKeys(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Create expired key directly in store.
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_expired1", Principal: "alice", Enabled: true,
		ExpiresAt: &past, CreatedAt: time.Now(),
	})
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_expired2", Principal: "bob", Enabled: true,
		ExpiresAt: &past, CreatedAt: time.Now(),
	})
	// Non-expired key.
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_valid", Principal: "carol", Enabled: true,
		ExpiresAt: &future, CreatedAt: time.Now(),
	})
	// Key with no expiry.
	mgr.Create(context.Background(), &store.KeyRecord{
		ID: "k_noexpiry", Principal: "dave", Enabled: true,
		CreatedAt: time.Now(),
	})

	// Purge expired.
	req := httptest.NewRequest("DELETE", "/admin/keys/expired", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("purge status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result struct {
		Deleted int64 `json:"deleted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &result)
	if result.Deleted != 2 {
		t.Errorf("deleted = %d, want 2", result.Deleted)
	}

	// Verify remaining keys.
	keys, _ := mgr.List(context.Background())
	if len(keys) != 2 {
		t.Fatalf("remaining = %d, want 2", len(keys))
	}
}

func TestUpdateAllowedCIDRs(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create a key.
	body := `{"principal":"alice","roles":["admin"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Set allowed CIDRs.
	cidrsBody := `{"allowed_cidrs":["10.0.0.0/8","192.168.1.0/24"]}`
	req = httptest.NewRequest("PUT", "/admin/keys/"+created.ID+"/allowed-cidrs", bytes.NewBufferString(cidrsBody))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set cidrs status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify stored.
	k, _ := mgr.GetByID(context.Background(), created.ID)
	if len(k.AllowedCIDRs) != 2 || k.AllowedCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("allowed_cidrs = %v, want [10.0.0.0/8 192.168.1.0/24]", k.AllowedCIDRs)
	}

	// Clear CIDRs.
	req = httptest.NewRequest("PUT", "/admin/keys/"+created.ID+"/allowed-cidrs", bytes.NewBufferString(`{"allowed_cidrs":[]}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clear cidrs status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	k, _ = mgr.GetByID(context.Background(), created.ID)
	if len(k.AllowedCIDRs) != 0 {
		t.Errorf("expected empty allowed_cidrs, got %v", k.AllowedCIDRs)
	}
}

func TestUpdateAllowedCIDRsInvalid(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create a key.
	body := `{"principal":"alice","roles":["admin"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Invalid CIDR should be rejected.
	cidrsBody := `{"allowed_cidrs":["not-a-cidr"]}`
	req = httptest.NewRequest("PUT", "/admin/keys/"+created.ID+"/allowed-cidrs", bytes.NewBufferString(cidrsBody))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid cidr status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPurgeExpiredDoesNotMatchSingleKeyRoute(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// DELETE /admin/keys/expired should not be routed to deleteKey with id="expired".
	req := httptest.NewRequest("DELETE", "/admin/keys/expired", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Should be 200 (purge response), not 500 (deleteKey with key not found).
	if rec.Code != http.StatusOK {
		t.Errorf("expected purge endpoint (200), got status %d", rec.Code)
	}
}

func newFullHandler() http.Handler {
	mgr := memory.NewStore()
	srv := admin.NewServer(":0", mgr, testKeygen, testToken, nil)
	return srv.Handler
}

func TestBodySizeLimit(t *testing.T) {
	h := newFullHandler()

	// 64 KiB + 1 byte should be rejected.
	oversized := strings.Repeat("x", 64*1024+1)
	body := `{"principal":"` + oversized + `","roles":["admin"]}`
	req := httptest.NewRequest("POST", "/admin/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRateLimitOnAdmin(t *testing.T) {
	h := newFullHandler()

	// Burst is 50 — send 55 requests, the last should be 429.
	var lastCode int
	for range 55 {
		req := httptest.NewRequest("GET", "/admin/keys", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		lastCode = rec.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after exceeding burst: status = %d, want %d", lastCode, http.StatusTooManyRequests)
	}
}

func TestUpdateRolesEmptyRejected(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	// Create a key.
	body := `{"principal":"alice","roles":["admin"]}`
	req := httptest.NewRequest("POST", "/admin/keys", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Update roles to empty should be rejected.
	req = httptest.NewRequest("PUT", "/admin/keys/"+created.ID+"/roles", bytes.NewBufferString(`{"roles":[]}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty roles update: status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	// Verify original roles unchanged.
	k, _ := mgr.GetByID(context.Background(), created.ID)
	if len(k.Roles) != 1 || k.Roles[0] != "admin" {
		t.Errorf("roles should be unchanged, got %v", k.Roles)
	}
}

func TestPrincipalTooLong(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	longPrincipal := strings.Repeat("a", 300)
	body := fmt.Sprintf(`{"principal":%q,"roles":["admin"]}`, longPrincipal)
	req := httptest.NewRequest("POST", "/admin/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("long principal: status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// auditFailStore wraps a KeyManager and makes AuditKeyEvent always fail.
type auditFailStore struct {
	store.KeyManager
}

func (s *auditFailStore) AuditKeyEvent(_ context.Context, _, _, _ string, _, _ any) error {
	return fmt.Errorf("audit backend unavailable")
}

func TestAuditFailureBlocksCreate(t *testing.T) {
	inner := memory.NewStore()
	mgr := &auditFailStore{inner}
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	body := `{"principal":"alice","roles":["admin"]}`
	req := httptest.NewRequest("POST", "/admin/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("create with audit failure: status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	// The just-created key must be compensated (deleted) so it is not left as an
	// unaudited, secret-lost orphan.
	keys, _ := inner.List(context.Background())
	if len(keys) != 0 {
		t.Errorf("expected created key to be deleted after audit failure, found %d keys", len(keys))
	}
}

func TestAuditFailureBlocksDelete(t *testing.T) {
	inner := memory.NewStore()
	inner.Create(context.Background(), &store.KeyRecord{
		ID: "k_del", Principal: "alice", Roles: []string{"admin"}, Enabled: true,
	})
	mgr := &auditFailStore{inner}
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	req := httptest.NewRequest("DELETE", "/admin/keys/k_del", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("delete with audit failure: status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	// The mutation applied (non-create mutations are not rolled back; the
	// inconsistency is flagged via audit_inconsistency_total for reconciliation).
	if got, _ := inner.GetByID(context.Background(), "k_del"); got != nil {
		t.Error("delete should have been applied despite the audit failure")
	}
}

func TestCreateKeyRejectsUnknownFieldAndPastExpiry(t *testing.T) {
	h := newFullHandler()
	cases := map[string]string{
		"unknown field":    `{"principal":"a","roles":["admin"],"bogus":1}`,
		"trailing garbage": `{"principal":"a","roles":["admin"]}{}`,
		"past expiry":      `{"principal":"a","roles":["admin"],"expires_at":"2000-01-01T00:00:00Z"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/admin/keys", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer test-token")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCreateKeyRejectsInvalidRoles(t *testing.T) {
	h := newFullHandler()
	cases := map[string]string{
		"empty role list": `{"principal":"a","roles":[]}`,
		"blank role":      `{"principal":"a","roles":["admin","  "]}`,
		"over-long role":  `{"principal":"a","roles":["` + strings.Repeat("x", 129) + `"]}`,
		"too many roles":  `{"principal":"a","roles":[` + strings.Repeat(`"r",`, 64) + `"r65"]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/admin/keys", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer test-token")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuditFailureBlocksRotate(t *testing.T) {
	inner := memory.NewStore()
	inner.Create(context.Background(), &store.KeyRecord{
		ID: "k_rot", KeyHash: "h", HmacKeyID: "v1", Principal: "alice",
		Roles: []string{"admin"}, Enabled: true,
	})
	mgr := &auditFailStore{inner}
	h := admin.Handler(mgr, testKeygen, testToken, nil)

	req := httptest.NewRequest("POST", "/admin/keys/k_rot/rotate", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("rotate with audit failure: status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	h := newFullHandler()

	// Exhaust burst for IP A.
	for range 55 {
		req := httptest.NewRequest("GET", "/admin/keys", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		req.RemoteAddr = "10.0.0.2:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}

	// IP B should still work.
	req := httptest.NewRequest("GET", "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.RemoteAddr = "10.0.0.3:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("different IP after rate limit: status = %d, want %d", rec.Code, http.StatusOK)
	}
}
