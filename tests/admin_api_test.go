package tests

import (
	"net/http"
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
		WithJSON(map[string]interface{}{
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
		WithJSON(map[string]interface{}{
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
