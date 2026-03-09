package tests

import (
	"net/http"
	"testing"
)

func TestReadZonesAllowsGETZones(t *testing.T) {
	keyID, secret := createTestKey(t, "rz-user", []string{"read_zones"})

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK).
		JSON().Array().NotEmpty()
}

func TestReadZonesAllowsGETSingleZone(t *testing.T) {
	keyID, secret := createTestKey(t, "rz-user-single", []string{"read_zones"})

	proxyClient(t).GET("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)
}

func TestReadZonesDeniesPATCH(t *testing.T) {
	keyID, secret := createTestKey(t, "rz-user-patch", []string{"read_zones"})

	proxyClient(t).PATCH("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		WithBytes([]byte(`{"rrsets":[]}`)).
		Expect().
		Status(http.StatusForbidden)
}

func TestReadZonesDenieGETServers(t *testing.T) {
	keyID, secret := createTestKey(t, "rz-user-servers", []string{"read_zones"})

	// GET /api/v1/servers is not a zones endpoint — should be denied.
	proxyClient(t).GET("/api/v1/servers").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusForbidden)
}

func TestAdminRoleAllowsEverything(t *testing.T) {
	keyID, secret := createTestKey(t, "admin-user", []string{"admin"})

	// GET zones
	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)

	// GET specific zone
	proxyClient(t).GET("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)
}

func TestNoRolesReturns403(t *testing.T) {
	keyID, secret := createTestKey(t, "no-roles-user", []string{})

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusForbidden)
}

func TestMultipleRolesFirstAllowWins(t *testing.T) {
	// A user with both read_zones and admin roles should be allowed for GET
	// (either plugin can ALLOW).
	keyID, secret := createTestKey(t, "multi-role-user", []string{"read_zones", "admin"})

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK)
}
