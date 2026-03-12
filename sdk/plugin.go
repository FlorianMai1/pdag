// Package sdk provides helpers for building PDAG authorization plugins.
// Plugin authors implement the Authorizer interface and call Serve().
package sdk

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	pb "github.com/mai/pdag/proto/authz"
)

// Handshake is the shared handshake config between PDAG and plugins.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PDAG_PLUGIN",
	MagicCookieValue: "authz",
}

// Authorizer is the interface plugin authors implement.
type Authorizer interface {
	Authorize(ctx context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error)
}

// Serve starts the plugin server. Call this from your plugin's main().
func Serve(impl Authorizer) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]plugin.Plugin{
			"authorizer": &AuthorizerPlugin{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// AuthorizerPlugin implements hashicorp/go-plugin's GRPCPlugin interface.
type AuthorizerPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	Impl Authorizer
}

func (p *AuthorizerPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterAuthorizerServer(s, &grpcServer{impl: p.Impl})
	return nil
}

func (p *AuthorizerPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &GRPCClient{client: pb.NewAuthorizerClient(c)}, nil
}

// grpcServer adapts the Authorizer interface to the gRPC server.
type grpcServer struct {
	pb.UnimplementedAuthorizerServer
	impl Authorizer
}

func (s *grpcServer) Authorize(ctx context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	return s.impl.Authorize(ctx, req)
}

// GRPCClient is the client-side implementation used by PDAG to call plugins.
type GRPCClient struct {
	client pb.AuthorizerClient
}

func (c *GRPCClient) Authorize(ctx context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
	return c.client.Authorize(ctx, req)
}
