package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mai/pdag/internal/admin"
	adminhmac "github.com/mai/pdag/internal/admin/hmac"
	"github.com/mai/pdag/internal/store/memory"
)

var (
	testKeygen = adminhmac.NewGenerator("v1", "test-secret")
	testToken  = "test-token"
)

func TestCreateAndListKeys(t *testing.T) {
	mgr := memory.NewStore()
	h := admin.Handler(mgr, testKeygen, testToken)

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
	h := admin.Handler(mgr, testKeygen, testToken)

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
	h := admin.Handler(mgr, testKeygen, testToken)

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
	h := admin.Handler(mgr, testKeygen, testToken)

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
