package httproute

import "testing"

func TestNormalizePathTrailingSlash(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Trailing slashes should be stripped before normalization.
		{"/api/v1/servers/localhost/zones/", "/api/v1/servers/:server_id/zones"},
		{"/api/v1/servers/localhost/zones/example.com./", "/api/v1/servers/:server_id/zones/:zone_id"},
		{"/api/v1/servers/localhost/", "/api/v1/servers/:server_id"},
		{"/api/v1/servers/", "/api/v1/servers"},
		{"/metrics/", "/metrics"},
		// Double trailing slashes.
		{"/api/v1/servers/localhost/zones//", "/api/v1/servers/:server_id/zones"},
	}

	for _, tt := range tests {
		got := Normalize(tt.input)
		if got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizePathBodyBytesMetric(t *testing.T) {
	// Verify various path structures normalize consistently.
	paths := map[string]string{
		"/api/v1/servers/srv1/zones/zone1/export":        "/api/v1/servers/:server_id/zones/:zone_id/export",
		"/api/v1/servers/srv1/zones/zone1/notify":        "/api/v1/servers/:server_id/zones/:zone_id/notify",
		"/api/v1/servers/srv1/zones/zone1/axfr-retrieve": "/api/v1/servers/:server_id/zones/:zone_id/axfr-retrieve",
		"/api/v1/servers/srv1/config":                    "/api/v1/servers/:server_id/config",
		"/api/v1/servers/srv1/statistics":                "/api/v1/servers/:server_id/statistics",
	}

	for path, want := range paths {
		got := Normalize(path)
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestNormalizePathDynamicTailAndUnknown(t *testing.T) {
	tests := map[string]string{
		// Zone sub-resource IDs must be masked (the cardinality leak).
		"/api/v1/servers/srv1/zones/z1./cryptokeys":        "/api/v1/servers/:server_id/zones/:zone_id/cryptokeys",
		"/api/v1/servers/srv1/zones/z1./cryptokeys/123":    "/api/v1/servers/:server_id/zones/:zone_id/cryptokeys/:cryptokey_id",
		"/api/v1/servers/srv1/zones/z1./metadata":          "/api/v1/servers/:server_id/zones/:zone_id/metadata",
		"/api/v1/servers/srv1/zones/z1./metadata/SOA-EDIT": "/api/v1/servers/:server_id/zones/:zone_id/metadata/:kind",
		// Known fixed endpoints kept verbatim.
		"/healthz": "/healthz",
		"/readyz":  "/readyz",
		"/":        "/",
		// Unknown / attacker-controlled paths fold to /other.
		"/foo/bar": "/other",
		"/api/v1/servers/srv1/zones/z1./unknownsub":           "/other",
		"/api/v1/servers/srv1/zones/z1./cryptokeys/123/extra": "/other",
		"/api/v2/servers":                  "/other",
		"/../../etc/passwd":                "/other",
		"/api/v1/servers/srv1/cache/flush": "/other",
	}

	for path, want := range tests {
		if got := Normalize(path); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", path, got, want)
		}
	}
}
