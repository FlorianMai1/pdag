// Plugin letsencrypt_dns_challenger allows only PATCH requests to zone endpoints
// where every RRset in the body is a TXT record with an _acme-challenge. prefix,
// and PUT requests to notify endpoints.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	pb "github.com/mai/pdag/proto/authz"
	"github.com/mai/pdag/sdk"
)

type challengerPlugin struct{}

// rrsetPatch represents the PowerDNS PATCH body for zone updates.
type rrsetPatch struct {
	RRSets []rrset `json:"rrsets"`
}

type rrset struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	ChangeType string `json:"changetype"`
}

func (p *challengerPlugin) Authorize(_ context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	path := req.Path

	// Allow PUT to notify endpoints: /api/v1/servers/{id}/zones/{zone}/notify
	if req.Method == "PUT" && strings.HasSuffix(path, "/notify") && isZoneSubpath(path) {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_ALLOW,
			Reason:   "letsencrypt: zone notify",
		}, nil
	}

	// Only allow PATCH to zone endpoints.
	if req.Method != "PATCH" || !isZonePath(path) {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_DENY,
			Reason:   fmt.Sprintf("letsencrypt: only PATCH to zones and PUT notify allowed, got %s %s", req.Method, path),
		}, nil
	}

	// Parse the body to validate RRsets.
	var patch rrsetPatch
	if err := json.Unmarshal(req.Body, &patch); err != nil {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_DENY,
			Reason:   fmt.Sprintf("letsencrypt: invalid JSON body: %s", err),
		}, nil
	}

	if len(patch.RRSets) == 0 {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_DENY,
			Reason:   "letsencrypt: empty rrsets",
		}, nil
	}

	for _, rr := range patch.RRSets {
		if rr.Type != "TXT" {
			return &pb.AuthorizeResponse{
				Decision: pb.Decision_DENY,
				Reason:   fmt.Sprintf("letsencrypt: only TXT records allowed, got %s", rr.Type),
			}, nil
		}
		if !strings.HasPrefix(rr.Name, "_acme-challenge.") {
			return &pb.AuthorizeResponse{
				Decision: pb.Decision_DENY,
				Reason:   fmt.Sprintf("letsencrypt: name must start with _acme-challenge., got %s", rr.Name),
			}, nil
		}

		// Validate that the underlying FQDN resolves.
		fqdn := strings.TrimPrefix(rr.Name, "_acme-challenge.")
		if !resolvable(fqdn) {
			return &pb.AuthorizeResponse{
				Decision: pb.Decision_DENY,
				Reason:   fmt.Sprintf("letsencrypt: FQDN %s does not resolve", fqdn),
			}, nil
		}
	}

	return &pb.AuthorizeResponse{
		Decision: pb.Decision_ALLOW,
		Reason:   "letsencrypt: valid ACME challenge records",
	}, nil
}

// isZonePath checks if the path matches /api/v1/servers/{id}/zones/{zone}
func isZonePath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	// api/v1/servers/{id}/zones/{zone} = 6 parts
	return len(parts) == 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "servers" && parts[4] == "zones"
}

// isZoneSubpath checks if the path is under a zone: /api/v1/servers/{id}/zones/{zone}/...
func isZoneSubpath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return len(parts) >= 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "servers" && parts[4] == "zones"
}

// resolvable checks if the FQDN has at least one A, AAAA, or CNAME record.
func resolvable(fqdn string) bool {
	// Try A/AAAA first.
	addrs, err := net.LookupHost(fqdn)
	if err == nil && len(addrs) > 0 {
		return true
	}
	// Try CNAME.
	cname, err := net.LookupCNAME(fqdn)
	return err == nil && cname != "" && cname != fqdn
}

func main() {
	sdk.Serve(&challengerPlugin{})
}
