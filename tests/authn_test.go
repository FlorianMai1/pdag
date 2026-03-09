package tests

import (
	"net/http"
	"testing"
)

func TestMissingAPIKeyReturns401(t *testing.T) {
	proxyClient(t).GET("/api/v1/servers").
		Expect().
		Status(http.StatusUnauthorized)
}

func TestMalformedAPIKeyReturns401(t *testing.T) {
	proxyClient(t).GET("/api/v1/servers").
		WithHeader("X-API-Key", "no-colon-here").
		Expect().
		Status(http.StatusUnauthorized)
}

func TestInvalidKeyIDReturns401(t *testing.T) {
	proxyClient(t).GET("/api/v1/servers").
		WithHeader("X-API-Key", "k_nonexistent:pdg_fakesecret").
		Expect().
		Status(http.StatusUnauthorized)
}

func TestValidKeyProxiesToPDNS(t *testing.T) {
	keyID, secret := createTestKey(t, "e2e-admin", []string{"admin"})

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK).
		JSON().Array().NotEmpty()
}

func TestDisabledKeyReturns401(t *testing.T) {
	keyID, secret := createTestKey(t, "disabled-user", []string{"admin"})

	// Disable the key.
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
}

func TestWrongSecretReturns401(t *testing.T) {
	keyID, _ := createTestKey(t, "wrong-secret-user", []string{"admin"})

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":pdg_completelywrongsecret").
		Expect().
		Status(http.StatusUnauthorized)
}
