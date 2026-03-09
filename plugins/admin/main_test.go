package main

import (
	"context"
	"testing"

	pb "github.com/mai/pdag/proto/authz"
)

func TestAdminAllowsEverything(t *testing.T) {
	p := &adminPlugin{}

	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/servers/localhost/zones"},
		{"PATCH", "/api/v1/servers/localhost/zones/example.com."},
		{"DELETE", "/api/v1/servers/localhost/zones/example.com."},
		{"POST", "/api/v1/servers/localhost/zones"},
		{"PUT", "/api/v1/servers/localhost/zones/example.com./notify"},
		{"GET", "/literally/anything"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: tt.method,
				Path:   tt.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != pb.Decision_ALLOW {
				t.Errorf("decision = %v, want ALLOW", resp.Decision)
			}
		})
	}
}
