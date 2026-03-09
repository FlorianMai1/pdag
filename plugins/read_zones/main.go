// Plugin read_zones allows only GET requests on the zones endpoint.
package main

import (
	"context"
	"regexp"

	pb "github.com/mai/pdag/proto/authz"
	"github.com/mai/pdag/sdk"
)

var allowedGetPaths = []*regexp.Regexp{
	regexp.MustCompile(`^/api/v1/servers/localhost/zones$`),
	regexp.MustCompile(`^/api/v1/servers/localhost/zones/[a-z0-9.-]+$`),
}

type readZonesPlugin struct{}

func (p *readZonesPlugin) Authorize(_ context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	if req.Method != "GET" {
		return &pb.AuthorizeResponse{
			Decision: pb.Decision_DENY,
			Reason:   "read_zones: only GET is allowed",
		}, nil
	}

	for _, re := range allowedGetPaths {
		if re.MatchString(req.Path) {
			return &pb.AuthorizeResponse{
				Decision: pb.Decision_ALLOW,
				Reason:   "read_zones: GET on zones endpoint",
			}, nil
		}
	}

	return &pb.AuthorizeResponse{
		Decision: pb.Decision_DENY,
		Reason:   "read_zones: path not allowed",
	}, nil
}

func main() {
	sdk.Serve(&readZonesPlugin{})
}
