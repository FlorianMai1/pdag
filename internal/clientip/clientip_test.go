package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRejectsInvalidCIDR(t *testing.T) {
	if _, err := New([]string{"not-a-cidr"}); err == nil {
		t.Error("expected error for invalid CIDR")
	}
	if _, err := New([]string{"10.0.0.0/8", "  192.168.0.0/16  "}); err != nil {
		t.Errorf("valid CIDRs (with whitespace) should parse: %v", err)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "no trusted proxies returns peer",
			remoteAddr: "203.0.113.5:443",
			xff:        "198.51.100.1", // must be ignored
			want:       "203.0.113.5",
		},
		{
			name:       "untrusted peer ignores spoofed XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.5:443",
			xff:        "198.51.100.1",
			want:       "203.0.113.5",
		},
		{
			name:       "trusted peer uses XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:443",
			xff:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "trusted peer with no XFF returns peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:443",
			want:       "10.0.0.1",
		},
		{
			name:       "multi-hop returns rightmost untrusted",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:443",
			xff:        "198.51.100.1, 203.0.113.9, 10.0.0.2",
			want:       "203.0.113.9",
		},
		{
			name:       "all hops trusted returns peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:443",
			xff:        "10.0.0.7, 10.0.0.8",
			want:       "10.0.0.1",
		},
		{
			name:       "malformed hop stops the chain at peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:443",
			xff:        "garbage, 10.0.0.2",
			want:       "10.0.0.1",
		},
		{
			name:       "ipv6 trusted peer uses XFF",
			trusted:    []string{"::1/128"},
			remoteAddr: "[::1]:443",
			xff:        "2001:db8::1",
			want:       "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.trusted)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := r.ClientIP(req)
			if got == nil {
				t.Fatalf("ClientIP returned nil, want %s", tt.want)
			}
			if got.String() != tt.want {
				t.Errorf("ClientIP = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClientIPUnparseablePeer(t *testing.T) {
	r, _ := New(nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-ip"
	if got := r.ClientIP(req); got != nil {
		t.Errorf("ClientIP = %v, want nil for unparseable peer", got)
	}
}
