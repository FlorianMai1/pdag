// Plugin admin allows all requests unconditionally.
package main

import (
	"context"

	pb "github.com/mai/pdag/proto/authz"
	"github.com/mai/pdag/sdk"
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
