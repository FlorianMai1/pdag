// Package plugin provides the go-plugin-based implementation of authz.Authorizer.
package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/mai/pdag/internal/authz"
	"github.com/mai/pdag/internal/metrics"
	pb "github.com/mai/pdag/proto/authz"
	"github.com/mai/pdag/sdk"
)

// Compile-time interface check.
var _ authz.Authorizer = (*Manager)(nil)

// pluginInstance holds a running plugin and its circuit breaker.
type pluginInstance struct {
	client     *plugin.Client
	authz      sdk.Authorizer
	breaker    *CircuitBreaker
	timeout    time.Duration
	cfg        authz.PluginConfig
	restarting atomic.Bool // true while a restart goroutine is running
	failed     atomic.Bool // true after all restart attempts are exhausted
}

// pluginMap is an immutable snapshot of plugin instances.
// Never mutate in place — always copy-on-write.
type pluginMap struct {
	m map[string]*pluginInstance
}

// Manager manages all authorization plugins.
type Manager struct {
	plugins atomic.Pointer[pluginMap] // lock-free reads
	writeMu sync.Mutex                // serializes mutations (restartPlugin, Close)
	done    chan struct{}              // closed on Close() to cancel in-flight restarts
	closed  atomic.Bool               // prevents restartPlugin from re-adding after Close
}

// NewManager creates a new plugin manager and starts all configured plugins.
// The caller is responsible for resolving defaults before passing the map.
func NewManager(plugins map[string]authz.PluginConfig) (*Manager, error) {
	m := &Manager{
		done: make(chan struct{}),
	}
	m.plugins.Store(&pluginMap{m: make(map[string]*pluginInstance)})

	instances := make(map[string]*pluginInstance, len(plugins))
	for name, pc := range plugins {
		inst, err := startPlugin(name, pc)
		if err != nil {
			// Clean up already-started plugins.
			for _, started := range instances {
				started.client.Kill()
			}
			return nil, fmt.Errorf("start plugin %q: %w", name, err)
		}

		instances[name] = inst
		slog.Info("plugin started", "name", name, "path", pc.Path)
	}

	m.plugins.Store(&pluginMap{m: instances})
	return m, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func startPlugin(name string, pc authz.PluginConfig) (*pluginInstance, error) {
	binHash, err := hashFile(pc.Path)
	if err != nil {
		slog.Warn("could not hash plugin binary", "plugin", name, "path", pc.Path, "error", err)
	} else {
		slog.Info("plugin binary loaded", "plugin", name, "path", pc.Path, "sha256", binHash)
	}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: sdk.Handshake,
		Plugins: map[string]plugin.Plugin{
			"authorizer": &sdk.AuthorizerPlugin{},
		},
		Cmd:              exec.Command(pc.Path),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("connect to plugin: %w", err)
	}

	raw, err := rpcClient.Dispense("authorizer")
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("dispense authorizer: %w", err)
	}

	authzImpl, ok := raw.(*sdk.GRPCClient)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("unexpected plugin type: %T", raw)
	}

	breaker := NewCircuitBreaker(
		name,
		pc.FailureThreshold,
		pc.SuccessThreshold,
		pc.Cooldown,
	)

	return &pluginInstance{
		client:  client,
		authz:   authzImpl,
		breaker: breaker,
		timeout: pc.Timeout,
		cfg:     pc,
	}, nil
}

// Authorize runs the authorization flow for the given roles.
// Returns the first ALLOW result, or DENY if all plugins deny.
// Uses fan-out with early cancellation on first ALLOW.
func (m *Manager) Authorize(ctx context.Context, roles []string, req *pb.HttpRequest) (decision string, pluginName string, reason string) {
	snap := m.plugins.Load()

	if len(roles) == 0 {
		return "deny", "", "no roles assigned"
	}

	type result struct {
		decision string
		plugin   string
		reason   string
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan result, len(roles))

	for _, role := range roles {
		inst, ok := snap.m[role]
		if !ok {
			slog.Warn("plugin not found for role", "role", role)
			resultCh <- result{"deny", role, "plugin not configured"}
			continue
		}

		go func(role string, inst *pluginInstance) {
			d, r := m.callPlugin(ctx, role, inst, req)
			resultCh <- result{d, role, r}
		}(role, inst)
	}

	// Collect results. First ALLOW wins.
	var lastDeny result
	for range roles {
		res := <-resultCh
		if res.decision == "allow" {
			cancel() // Cancel remaining in-flight calls.
			return res.decision, res.plugin, res.reason
		}
		lastDeny = res
	}

	return lastDeny.decision, lastDeny.plugin, lastDeny.reason
}

func (m *Manager) callPlugin(ctx context.Context, name string, inst *pluginInstance, req *pb.HttpRequest) (decision string, reason string) {
	// Permanently failed plugins are not retried.
	if inst.failed.Load() {
		metrics.AuthzDecisionTotal.WithLabelValues(name, "failed").Inc()
		return "deny", fmt.Sprintf("plugin permanently failed: %s", name)
	}

	// Check circuit breaker first.
	if !inst.breaker.Allow() {
		metrics.AuthzDecisionTotal.WithLabelValues(name, "circuit_open").Inc()
		return "deny", fmt.Sprintf("circuit open: %s", name)
	}

	// Apply per-plugin timeout.
	callCtx, cancel := context.WithTimeout(ctx, inst.timeout)
	defer cancel()

	start := time.Now()
	resp, err := inst.authz.Authorize(callCtx, req)
	duration := time.Since(start).Seconds()

	metrics.AuthzPluginDuration.WithLabelValues(name).Observe(duration)

	if err != nil {
		inst.breaker.RecordFailure()
		if callCtx.Err() == context.DeadlineExceeded {
			metrics.AuthzDecisionTotal.WithLabelValues(name, "timeout").Inc()
			return "deny", fmt.Sprintf("timeout: %s", name)
		}
		metrics.AuthzDecisionTotal.WithLabelValues(name, "error").Inc()
		slog.Error("plugin call failed", "plugin", name, "error", err)

		// If the plugin process has exited, attempt restart (one at a time).
		if inst.client.Exited() && !inst.failed.Load() && inst.restarting.CompareAndSwap(false, true) {
			slog.Warn("plugin process exited, scheduling restart", "plugin", name)
			go m.restartPlugin(name, inst.cfg)
		}

		return "deny", fmt.Sprintf("error: %s: %s", name, err)
	}

	inst.breaker.RecordSuccess()

	switch resp.Decision {
	case pb.Decision_ALLOW:
		metrics.AuthzDecisionTotal.WithLabelValues(name, "allow").Inc()
		return "allow", resp.Reason
	default:
		metrics.AuthzDecisionTotal.WithLabelValues(name, "deny").Inc()
		return "deny", resp.Reason
	}
}

// swapPlugin performs a copy-on-write map replacement. Must hold writeMu.
func (m *Manager) swapPlugin(name string, newInst *pluginInstance) *pluginInstance {
	current := m.plugins.Load()
	newMap := make(map[string]*pluginInstance, len(current.m))
	for k, v := range current.m {
		newMap[k] = v
	}
	old := newMap[name]
	newMap[name] = newInst
	m.plugins.Store(&pluginMap{m: newMap})
	return old
}

// restartPlugin attempts to restart a crashed plugin with exponential backoff.
// It respects the Manager's done channel for graceful shutdown.
func (m *Manager) restartPlugin(name string, pc authz.PluginConfig) {
	backoff := []time.Duration{
		1 * time.Second, 2 * time.Second, 5 * time.Second,
		10 * time.Second, 30 * time.Second,
	}
	for attempt, delay := range backoff {
		select {
		case <-m.done:
			slog.Info("plugin restart cancelled by shutdown", "plugin", name)
			return
		case <-time.After(delay):
		}

		newInst, err := startPlugin(name, pc)
		if err != nil {
			slog.Error("plugin restart failed", "plugin", name, "attempt", attempt+1, "error", err)
			continue
		}

		// Reset circuit breaker so the fresh instance can prove health immediately.
		newInst.breaker = NewCircuitBreaker(
			name,
			pc.FailureThreshold,
			pc.SuccessThreshold,
			pc.Cooldown,
		)

		m.writeMu.Lock()
		if m.closed.Load() {
			m.writeMu.Unlock()
			newInst.client.Kill()
			return
		}
		old := m.swapPlugin(name, newInst)
		m.writeMu.Unlock()

		if old != nil {
			old.client.Kill()
		}
		slog.Info("plugin restarted successfully", "plugin", name, "attempt", attempt+1)
		return
	}

	// All attempts exhausted — mark plugin as permanently failed to prevent
	// infinite restart loops from callPlugin detecting the dead process.
	m.writeMu.Lock()
	snap := m.plugins.Load()
	if inst, ok := snap.m[name]; ok {
		inst.failed.Store(true)
	}
	m.writeMu.Unlock()
	slog.Error("plugin restart exhausted all attempts, marked as permanently failed", "plugin", name)
}

// Close cancels in-flight restarts and kills all plugin subprocesses.
func (m *Manager) Close() {
	close(m.done) // signal restart goroutines to stop
	m.closed.Store(true)

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	snap := m.plugins.Load()
	m.plugins.Store(&pluginMap{m: make(map[string]*pluginInstance)})

	for name, inst := range snap.m {
		inst.client.Kill()
		slog.Info("plugin stopped", "name", name)
	}
}

// HasPlugins returns true if any plugins are configured.
func (m *Manager) HasPlugins() bool {
	return len(m.plugins.Load().m) > 0
}

// Healthy returns true if at least one plugin process is alive and not
// permanently failed. Used by the readiness probe.
func (m *Manager) Healthy() bool {
	for _, inst := range m.plugins.Load().m {
		if !inst.failed.Load() && !inst.client.Exited() {
			return true
		}
	}
	return false
}
