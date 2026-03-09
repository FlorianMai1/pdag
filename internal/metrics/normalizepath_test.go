package metrics

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
		got := normalizePath(tt.input)
		if got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
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
		got := normalizePath(path)
		if got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", path, got, want)
		}
	}
}
