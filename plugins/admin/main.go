// Plugin admin allows all requests unconditionally.
package main

import (
	"context"

	pb "github.com/FlorianMai1/pdag/proto/authz"
	"github.com/FlorianMai1/pdag/sdk"
)

type adminPlugin struct{}

func (p *adminPlugin) Authorize(_ context.Context, _ *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	return &pb.AuthorizeResponse{
		Decision: pb.Decision_ALLOW,
		Reason:   "admin: full access",
	}, nil
}

func main() {
	sdk.Serve(&adminPlugin{})
}
