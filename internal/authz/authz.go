// Package authz provides the authorization interface and middleware for PDAG.
// The plugin-based implementation lives in the authz/plugin subpackage.
package authz

import (
	"context"
	"time"

	pb "github.com/FlorianMai1/pdag/proto/authz"
)

// Authorizer evaluates authorization decisions for a set of roles.
type Authorizer interface {
	Authorize(ctx context.Context, roles []string, req *pb.HttpRequest) (decision string, pluginName string, reason string)
}

// PluginConfig holds the resolved configuration for a single authorization plugin.
type PluginConfig struct {
	Path             string
	SHA256           string
	Timeout          time.Duration
	FailureThreshold int
	SuccessThreshold int
	Cooldown         time.Duration
}
