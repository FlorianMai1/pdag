// Plugin api_discovery allows only GET /api for PowerDNS API version discovery.
package main

import (
	"context"
	"fmt"

	pb "github.com/FlorianMai1/pdag/proto/authz"
	"github.com/FlorianMai1/pdag/sdk"
)

type discoveryPlugin struct{}

func (p *discoveryPlugin) Authorize(_ context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	if req.Method == "GET" && req.Path == "/api" {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_ALLOW,
			Reason:   "api_discovery: version discovery",
		}, nil
	}

	return &pb.AuthorizeResponse{
		Decision: pb.Decision_DENY,
		Reason:   fmt.Sprintf("api_discovery: only GET /api allowed, got %s %s", req.Method, req.Path),
	}, nil
}

func main() {
	sdk.Serve(&discoveryPlugin{})
}
