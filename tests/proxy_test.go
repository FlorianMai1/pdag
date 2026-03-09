package tests

import (
	"net/http"
	"testing"
)

func TestProxyPreservesResponseBody(t *testing.T) {
	keyID, secret := createTestKey(t, "proxy-body-test", []string{"admin"})

	// GET a specific zone — response should contain the zone data.
	proxyClient(t).GET("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		Value("name").IsEqual("example.com.")
}

func TestProxyPreservesQueryParams(t *testing.T) {
	keyID, secret := createTestKey(t, "proxy-query-test", []string{"admin"})

	// PowerDNS supports ?rrsets=false to omit records from zone response.
	proxyClient(t).GET("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		WithQuery("rrsets", "false").
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		Value("name").IsEqual("example.com.")
}

func TestProxySetsRequestID(t *testing.T) {
	keyID, secret := createTestKey(t, "requestid-test", []string{"admin"})

	proxyClient(t).GET("/api/v1/servers/localhost/zones").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK).
		Header("X-Request-ID").NotEmpty()
}

func TestProxyPATCHZone(t *testing.T) {
	keyID, secret := createTestKey(t, "patch-test", []string{"admin"})

	// Add a TXT record via PATCH.
	body := `{
		"rrsets": [{
			"name": "e2e-test.example.com.",
			"type": "TXT",
			"ttl": 300,
			"changetype": "REPLACE",
			"records": [{"content": "\"e2e-test-value\"", "disabled": false}]
		}]
	}`

	proxyClient(t).PATCH("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		WithHeader("Content-Type", "application/json").
		WithBytes([]byte(body)).
		Expect().
		Status(http.StatusNoContent)

	// Verify the record was created.
	proxyClient(t).GET("/api/v1/servers/localhost/zones/example.com.").
		WithHeader("X-API-Key", keyID+":"+secret).
		Expect().
		Status(http.StatusOK).
		Body().Contains("e2e-test.example.com.")
}
