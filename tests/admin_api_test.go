package tests

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gavv/httpexpect/v2"
)

func TestAdminAPIRequiresAuth(t *testing.T) {
	// No token.
	adminClient(t).GET("/admin/keys").
		Expect().
		Status(http.StatusUnauthorized)

	// Wrong token.
	adminClient(t).GET("/admin/keys").
		WithHeader("Authorization", "Bearer wrong-token").
		Expect().
		Status(http.StatusUnauthorized)
}

func TestAdminAPICreateListDeleteKey(t *testing.T) {
	// Create.
	resp := adminClient(t).POST("/admin/keys").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"principal": "lifecycle-test",
			"roles":     []string{"read_zones"},
		}).
		Expect().
		Status(http.StatusCreated).
		JSON().Object()

	keyID := resp.Value("id").String().Raw()
	resp.Value("secret").String().NotEmpty()
	resp.Value("principal").IsEqual("lifecycle-test")

	// List — should contain the new key.
	adminClient(t).GET("/admin/keys").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusOK).
		JSON().Array().
		Find(func(_ int, val *httpexpect.Value) bool {
			return val.Object().Value("id").String().Raw() == keyID
		}).Object().Value("principal").IsEqual("lifecycle-test")

	// Delete.
	adminClient(t).DELETE("/admin/keys/{id}").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusNoContent)

	// Verify deleted — list should not contain it.
	adminClient(t).GET("/admin/keys").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusOK).
		JSON().Array().
		NotFind(func(_ int, val *httpexpect.Value) bool {
			return val.Object().Value("id").String().Raw() == keyID
		})
}

func TestAdminAPIUpdateRoles(t *testing.T) {
	keyID, _ := createTestKey(t, "roles-update-test", []string{"read_zones"})

	// Update roles to admin.
	adminClient(t).PUT("/admin/keys/{id}/roles").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"roles": []string{"admin"},
		}).
		Expect().
		Status(http.StatusNoContent)

	// Verify via list.
	adminClient(t).GET("/admin/keys").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusOK).
		JSON().Array().
		Find(func(_ int, val *httpexpect.Value) bool {
			return val.Object().Value("id").String().Raw() == keyID
		}).Object().Value("roles").Array().IsEqual([]string{"admin"})
}

func TestAdminAPIRotateKey(t *testing.T) {
	keyID, oldSecret := createTestKey(t, "rotate-test", []string{"admin"})

	// Old secret works.
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+oldSecret).
		Expect().
		Status(http.StatusOK)

	// Rotate.
	rotateResp := adminClient(t).POST("/admin/keys/{id}/rotate").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	rotateResp.Value("id").IsEqual(keyID)
	newSecret := rotateResp.Value("secret").String().NotEmpty().Raw()

	// Old secret should fail.
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+oldSecret).
		Expect().
		Status(http.StatusUnauthorized)

	// New secret should work.
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+newSecret).
		Expect().
		Status(http.StatusOK)
}

func TestAdminAPIRotateKeyNotFound(t *testing.T) {
	adminClient(t).POST("/admin/keys/{id}/rotate").
		WithPath("id", "k_nonexistent").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusNotFound)
}

func TestAdminAPIDeleteKeyNotFound(t *testing.T) {
	adminClient(t).DELETE("/admin/keys/{id}").
		WithPath("id", "k_nonexistent").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusNotFound)
}

func TestAdminAPIUpdateAllowedCIDRs(t *testing.T) {
	keyID, secret := createTestKey(t, "cidr-test", []string{"admin"})

	// Set allowed CIDRs to localhost only (both IPv4 and IPv6 loopback).
	adminClient(t).PUT("/admin/keys/{id}/allowed-cidrs").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"allowed_cidrs": []string{"127.0.0.0/8", "::1/128"},
		}).
		Expect().
		Status(http.StatusNoContent)

	// Should still work (test runs on localhost).
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)

	// Set to a non-matching CIDR.
	adminClient(t).PUT("/admin/keys/{id}/allowed-cidrs").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"allowed_cidrs": []string{"10.99.99.0/24"},
		}).
		Expect().
		Status(http.StatusNoContent)

	// Should be denied (client IP is 127.0.0.1, not in 10.99.99.0/24).
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusForbidden)

	// Clear allowed CIDRs — should work again.
	adminClient(t).PUT("/admin/keys/{id}/allowed-cidrs").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"allowed_cidrs": []string{},
		}).
		Expect().
		Status(http.StatusNoContent)

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)
}

func TestAdminAPIUpdateAllowedCIDRsInvalidCIDR(t *testing.T) {
	keyID, _ := createTestKey(t, "cidr-invalid-test", []string{"admin"})

	adminClient(t).PUT("/admin/keys/{id}/allowed-cidrs").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"allowed_cidrs": []string{"not-a-cidr"},
		}).
		Expect().
		Status(http.StatusBadRequest)
}

func TestAdminAPIPrincipalLengthLimit(t *testing.T) {
	longPrincipal := strings.Repeat("a", 300)

	adminClient(t).POST("/admin/keys").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"principal": longPrincipal,
			"roles":     []string{"admin"},
		}).
		Expect().
		Status(http.StatusBadRequest)
}

func TestAdminAPIDisableEnable(t *testing.T) {
	keyID, secret := createTestKey(t, "disable-enable-test", []string{"admin"})

	// Should work initially.
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)

	// Disable.
	adminClient(t).PATCH("/admin/keys/{id}/disable").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusNoContent)

	// Should be rejected.
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusUnauthorized)

	// Re-enable.
	adminClient(t).PATCH("/admin/keys/{id}/enable").
		WithPath("id", keyID).
		WithHeader("Authorization", "Bearer e2e-admin-token").
		Expect().
		Status(http.StatusNoContent)

	// Should work again.
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)
}
