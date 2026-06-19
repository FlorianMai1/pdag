package main

import (
	"context"
	"testing"

	pb "github.com/FlorianMai1/pdag/proto/authz"
)

func TestAllowsGETApi(t *testing.T) {
	p := &discoveryPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Path:   "/api",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_ALLOW {
		t.Errorf("decision = %v (%s), want ALLOW", resp.Decision, resp.Reason)
	}
}

func TestDeniesNonGET(t *testing.T) {
	p := &discoveryPlugin{}

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: method,
				Path:   "/api",
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

func TestDeniesOtherPaths(t *testing.T) {
	p := &discoveryPlugin{}

	paths := []string{
		"/api/v1/servers",
		"/api/v1/servers/localhost/zones",
		"/api/",
		"/",
		"/something",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: "GET",
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
