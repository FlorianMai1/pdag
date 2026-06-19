// Plugin zone_notify allows only PUT requests to zone notify endpoints.
package main

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/FlorianMai1/pdag/proto/authz"
	"github.com/FlorianMai1/pdag/sdk"
)

type notifyPlugin struct{}

func (p *notifyPlugin) Authorize(_ context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	if req.Method == "PUT" && strings.HasSuffix(req.Path, "/notify") && isZoneSubpath(req.Path) {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_ALLOW,
			Reason:   "zone_notify: zone notify",
		}, nil
	}

	return &pb.AuthorizeResponse{
		Decision: pb.Decision_DENY,
		Reason:   fmt.Sprintf("zone_notify: only PUT to zone notify allowed, got %s %s", req.Method, req.Path),
	}, nil
}

// isZoneSubpath checks if the path is under a zone: /api/v1/servers/{id}/zones/{zone}/...
func isZoneSubpath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return len(parts) >= 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "servers" && parts[4] == "zones"
}

func main() {
	sdk.Serve(&notifyPlugin{})
}
