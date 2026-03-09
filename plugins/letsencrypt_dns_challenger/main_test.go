package main

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/mai/pdag/proto/authz"
)

func makeBody(t *testing.T, patch rrsetPatch) []byte {
	t.Helper()
	b, err := json.Marshal(patch)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeniesNonPATCHNonPUT(t *testing.T) {
	p := &challengerPlugin{}

	for _, method := range []string{"GET", "DELETE", "POST"} {
		t.Run(method, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: method,
				Path:   "/api/v1/servers/localhost/zones/example.com.",
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

func TestAllowsPUTNotify(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PUT",
		Path:   "/api/v1/servers/localhost/zones/example.com./notify",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_ALLOW {
		t.Errorf("decision = %v (%s), want ALLOW for PUT notify", resp.Decision, resp.Reason)
	}
}

func TestDeniesPUTNonNotify(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PUT",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v, want DENY for PUT to non-notify path", resp.Decision)
	}
}

func TestDeniesPATCHNonZonePath(t *testing.T) {
	p := &challengerPlugin{}

	paths := []string{
		"/api/v1/servers/localhost/zones",
		"/api/v1/servers",
		"/something/else",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
				Method: "PATCH",
				Path:   path,
				Body: makeBody(t, rrsetPatch{RRSets: []rrset{
					{Name: "_acme-challenge.example.com.", Type: "TXT", ChangeType: "REPLACE"},
				}}),
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

func TestDeniesInvalidJSON(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body:   []byte(`{not json`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v, want DENY for invalid JSON", resp.Decision)
	}
}

func TestDeniesEmptyRRSets(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body:   makeBody(t, rrsetPatch{RRSets: []rrset{}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v (%s), want DENY for empty rrsets", resp.Decision, resp.Reason)
	}
}

func TestDeniesNonTXTRecord(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body: makeBody(t, rrsetPatch{RRSets: []rrset{
			{Name: "_acme-challenge.example.com.", Type: "A", ChangeType: "REPLACE"},
		}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v (%s), want DENY for A record", resp.Decision, resp.Reason)
	}
}

func TestDeniesNonAcmePrefix(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body: makeBody(t, rrsetPatch{RRSets: []rrset{
			{Name: "www.example.com.", Type: "TXT", ChangeType: "REPLACE"},
		}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v (%s), want DENY for non-acme prefix", resp.Decision, resp.Reason)
	}
}

func TestDeniesUnresolvableFQDN(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body: makeBody(t, rrsetPatch{RRSets: []rrset{
			{Name: "_acme-challenge.this-domain-does-not-exist-xyzzy.invalid.", Type: "TXT", ChangeType: "REPLACE"},
		}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v (%s), want DENY for unresolvable FQDN", resp.Decision, resp.Reason)
	}
}

func TestAllowsValidAcmeChallenge(t *testing.T) {
	p := &challengerPlugin{}

	// Uses a well-known resolvable domain.
	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body: makeBody(t, rrsetPatch{RRSets: []rrset{
			{Name: "_acme-challenge.example.com.", Type: "TXT", ChangeType: "REPLACE"},
		}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_ALLOW {
		t.Errorf("decision = %v (%s), want ALLOW for valid ACME challenge", resp.Decision, resp.Reason)
	}
}

func TestDeniesMixedRecordTypes(t *testing.T) {
	p := &challengerPlugin{}

	resp, err := p.Authorize(context.Background(), &pb.HttpRequest{
		Method: "PATCH",
		Path:   "/api/v1/servers/localhost/zones/example.com.",
		Body: makeBody(t, rrsetPatch{RRSets: []rrset{
			{Name: "_acme-challenge.example.com.", Type: "TXT", ChangeType: "REPLACE"},
			{Name: "_acme-challenge.example.com.", Type: "A", ChangeType: "REPLACE"},
		}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != pb.Decision_DENY {
		t.Errorf("decision = %v (%s), want DENY for mixed record types", resp.Decision, resp.Reason)
	}
}

func TestIsZonePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/servers/localhost/zones/example.com.", true},
		{"/api/v1/servers/localhost/zones/sub.example.com.", true},
		{"/api/v1/servers/localhost/zones", false},
		{"/api/v1/servers/localhost/zones/example.com./notify", false},
		{"/something/else", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isZonePath(tt.path); got != tt.want {
				t.Errorf("isZonePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
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
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isZoneSubpath(tt.path); got != tt.want {
				t.Errorf("isZoneSubpath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
