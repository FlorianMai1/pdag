package metrics

import "testing"

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/api/v1/servers/localhost/zones", "/api/v1/servers/:server_id/zones"},
		{"/api/v1/servers/localhost/zones/example.com.", "/api/v1/servers/:server_id/zones/:zone_id"},
		{"/api/v1/servers/localhost/zones/example.com./notify", "/api/v1/servers/:server_id/zones/:zone_id/notify"},
		{"/api/v1/servers/localhost", "/api/v1/servers/:server_id"},
		{"/api/v1/servers", "/api/v1/servers"},
		{"/api/v1/servers/localhost/zones/", "/api/v1/servers/:server_id/zones"},
		{"/api/v1/servers/localhost/zones/example.com./", "/api/v1/servers/:server_id/zones/:zone_id"},
		{"/metrics", "/metrics"},
		{"/", "/"},
	}

	for _, tt := range tests {
		got := normalizePath(tt.input)
		if got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
