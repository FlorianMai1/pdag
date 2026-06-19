package main

import (
	"context"
	"testing"

	pb "github.com/FlorianMai1/pdag/proto/authz"
)

func TestAllowsPUTNotify(t *testing.T) {
	p := &notifyPlugin{}

	paths := []string{
		"/api/v1/servers/localhost/zones/example.com./notify",
		"/api/v1/servers/localhost/zones/sub.example.com./notify",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: "PUT",
				Path:   path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != pb.Decision_ALLOW {
				t.Errorf("decision = %v (%s), want ALLOW", resp.Decision, resp.Reason)
			}
		})
	}
}

func TestDeniesPUTNonNotify(t *testing.T) {
	p := &notifyPlugin{}

	paths := []string{
		"/api/v1/servers/localhost/zones/example.com.",
		"/api/v1/servers/localhost/zones",
		"/api/v1/servers/localhost/zones/example.com./export",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: "PUT",
				Path:   path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != pb.Decision_DENY {
				t.Errorf("decision = %v (%s), want DENY", resp.Decision, resp.Reason)
			}
		})
	}
}

func TestDeniesNonPUT(t *testing.T) {
	p := &notifyPlugin{}

	for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: method,
				Path:   "/api/v1/servers/localhost/zones/example.com./notify",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != pb.Decision_DENY {
				t.Errorf("decision = %v (%s), want DENY for %s", resp.Decision, resp.Reason, method)
			}
		})
	}
}

func TestDeniesNotifyOnNonZonePath(t *testing.T) {
	p := &notifyPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PUT",
		Path:   "/something/notify",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v (%s), want DENY for non-zone notify path", resp.Decision, resp.Reason)
	}
}

func TestIsZoneSubpath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/servers/localhost/zones/example.com.", true},
		{"/api/v1/servers/localhost/zones/example.com./notify", true},
		{"/api/v1/servers/localhost/zones", false},
		{"/api/v1/servers", false},
		{"/something/notify", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isZoneSubpath(tt.path); got != tt.want {
				t.Errorf("isZoneSubpath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
