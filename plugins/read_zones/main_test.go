package main

import (
	"context"
	"testing"

	pb "github.com/mai/pdag/proto/authz"
)

func TestReadZonesAllowsGET(t *testing.T) {
	p := &readZonesPlugin{}

	tests := []struct {
		name string
		path string
	}{
		{"list zones", "/api/v1/servers/localhost/zones"},
		{"get zone", "/api/v1/servers/localhost/zones/example.com."},
		{"get zone no dot", "/api/v1/servers/localhost/zones/example.com"},
		{"subdomain zone", "/api/v1/servers/localhost/zones/sub.example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: "GET",
				Path:   tt.path,
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

func TestReadZonesDeniesNonGET(t *testing.T) {
	p := &readZonesPlugin{}

	for _, method := range []string{"POST", "PATCH", "DELETE", "PUT"} {
		t.Run(method, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: method,
				Path:   "/api/v1/servers/localhost/zones",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != pb.Decision_DENY {
				t.Errorf("decision = %v, want DENY for %s", resp.Decision, method)
			}
		})
	}
}

func TestReadZonesDeniesOtherPaths(t *testing.T) {
	p := &readZonesPlugin{}

	tests := []struct {
		name string
		path string
	}{
		{"servers root", "/api/v1/servers"},
		{"server info", "/api/v1/servers/localhost"},
		{"zone subpath", "/api/v1/servers/localhost/zones/example.com./notify"},
		{"random path", "/something/else"},
		{"empty", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: "GET",
				Path:   tt.path,
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
