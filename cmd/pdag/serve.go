package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mai/pdag/internal/admin"
	adminhmac "github.com/mai/pdag/internal/admin/hmac"
	"github.com/mai/pdag/internal/audit"
	auditfile "github.com/mai/pdag/internal/audit/file"
	"github.com/mai/pdag/internal/authn"
	"github.com/mai/pdag/internal/authn/hmac"
	"github.com/mai/pdag/internal/authz"
	authzplugin "github.com/mai/pdag/internal/authz/plugin"
	"github.com/mai/pdag/internal/clientip"
	"github.com/mai/pdag/internal/config"
	"github.com/mai/pdag/internal/metrics"
	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/proxy"
	"github.com/mai/pdag/internal/proxy/balancer"
	"github.com/mai/pdag/internal/proxy/single"
	"github.com/mai/pdag/internal/ratelimit"
	"github.com/mai/pdag/internal/ratelimit/token"
	"github.com/mai/pdag/internal/store"
	"github.com/mai/pdag/internal/store/memory"
	"github.com/mai/pdag/internal/store/postgres"
	"github.com/mai/pdag/internal/tracing"
)

func runServe() error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	slog.Info("starting pdag", "listen", cfg.Listen, "backends", len(cfg.Upstreams.Backends), "metrics", cfg.Metrics.Listen)

	if cfg.Tracing.Enabled {
		shutdownTracer, tracerErr := tracing.Init(context.Background(), tracing.Config{
			Endpoint:   cfg.Tracing.Endpoint,
			Insecure:   cfg.Tracing.Insecure,
			SampleRate: cfg.Tracing.SampleRate,
		})
		if tracerErr != nil {
			return fmt.Errorf("init tracing: %w", tracerErr)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if shutdownErr := shutdownTracer(shutdownCtx); shutdownErr != nil {
				slog.Error("shutdown tracer", "error", shutdownErr)
			}
		}()
		slog.Info("tracing enabled", "endpoint", cfg.Tracing.Endpoint, "sample_rate", cfg.Tracing.SampleRate)
	}

	keyStore, closeStore, err := openKeyStore(cfg.DB.DSN)
	if err != nil {
		return err
	}
	defer closeStore()

	auditPub, reopenAudit, closeAudit, err := openAuditLog(cfg.AuditLog, cfg.AuditBufferSize, cfg.AuditEnqueueTimeout)
	if err != nil {
		return err
	}
	defer closeAudit()

	pluginMgr, err := openPluginManager(cfg)
	if err != nil {
		return err
	}
	defer pluginMgr.Close()

	backend, err := openBackend(&cfg.Upstreams)
	if err != nil {
		return err
	}
	defer backend.Close()

	// Build HMAC secret map for the authn service.
	hmacSecrets := make(map[string]string, len(cfg.HmacSecrets))
	for _, s := range cfg.HmacSecrets {
		hmacSecrets[s.ID] = s.Secret
	}
	hmacService := hmac.NewHmacService(hmacSecrets)

	limiter := openRateLimiter(cfg)

	resolver, err := clientip.New(cfg.TrustedProxies)
	if err != nil {
		return fmt.Errorf("build client IP resolver: %w", err)
	}
	if len(cfg.TrustedProxies) > 0 {
		slog.Info("trusted proxies configured for client IP resolution", "count", len(cfg.TrustedProxies))
	}

	auditOpts := audit.Options{LogBody: cfg.AuditLogBody, FailClosed: cfg.AuditFailClosed}
	proxySrv := newProxyServer(cfg.Listen, cfg.MaxBodySize, auditOpts, limiter, backend, keyStore, auditPub, pluginMgr, hmacService, resolver)

	// Extract current HMAC secret for admin key generation.
	currentHmac, err := cfg.CurrentHmacSecret()
	if err != nil {
		return fmt.Errorf("hmac secret: %w", err)
	}
	keygen := adminhmac.NewGenerator(currentHmac.ID, currentHmac.Secret)

	metricsSrv := metrics.NewServer(cfg.Metrics.Listen)
	adminSrv := newAdminServer(cfg.Admin.Listen, cfg.AdminToken, keygen, keyStore)

	// Create the signal context shared by all background goroutines.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	sighupDone := make(chan struct{})
	go handleSIGHUP(reopenAudit, sighupDone)

	// Start automatic expired key cleanup if configured.
	if cfg.KeyCleanupInterval > 0 {
		if keyMgr, ok := keyStore.(store.KeyManager); ok {
			go runKeyCleanup(ctx, cfg.KeyCleanupInterval, keyMgr)
			slog.Info("automatic key cleanup enabled", "interval", cfg.KeyCleanupInterval)
		}
	}

	err = listenAndServe(ctx, cfg.ShutdownWait, proxySrv, metricsSrv, adminSrv)

	// Stop SIGHUP handler after server shutdown.
	close(sighupDone)
	return err
}

// ── Factory functions ────────────────────────────────────────────────

func openKeyStore(dsn string) (store.KeyStore, func(), error) {
	if dsn != "" {
		migrationsPath, err := filepath.Abs("migrations")
		if err != nil {
			return nil, func() {}, fmt.Errorf("resolve migrations path: %w", err)
		}
		if _, statErr := os.Stat(migrationsPath); statErr != nil {
			return nil, func() {}, fmt.Errorf("migrations directory %q: %w", migrationsPath, statErr)
		}
		pg, err := postgres.NewStore(dsn, migrationsPath)
		if err != nil {
			return nil, func() {}, fmt.Errorf("open postgres store: %w", err)
		}
		slog.Info("connected to postgres key store")
		metrics.NewDBPoolCollector(pg.DB())
		return pg, func() { pg.Close() }, nil
	}

	slog.Warn("no database configured, using in-memory key store (development only)")
	mem := memory.NewStore()
	return mem, func() {}, nil
}

func openAuditLog(path string, bufSize int, enqueueTimeout time.Duration) (audit.Publisher, func() error, func(), error) {
	if path == "" {
		slog.Warn("no audit_log configured, audit logging disabled")
		return audit.Noop(), func() error { return nil }, func() {}, nil
	}

	al, err := auditfile.NewLogger(path, bufSize, enqueueTimeout)
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("open audit log: %w", err)
	}
	slog.Info("audit log enabled", "path", path)
	return al, al.Reopen, func() { al.Close() }, nil
}

func openRateLimiter(cfg *config.Config) ratelimit.RateLimiter {
	if !cfg.RateLimit.Enabled {
		return ratelimit.Noop()
	}
	slog.Info("rate limiting enabled", "rate", cfg.RateLimit.Rate, "burst", cfg.RateLimit.Burst)
	return token.New(token.Config{
		Rate:  cfg.RateLimit.Rate,
		Burst: cfg.RateLimit.Burst,
	})
}

func openBackend(upstreams *config.Upstreams) (proxy.Backend, error) {
	if len(upstreams.Backends) == 1 {
		b := upstreams.Backends[0]
		slog.Info("single upstream backend", "url", b.URL)
		return single.New(b.URL, b.APIKey)
	}

	backends := make([]balancer.Backend, len(upstreams.Backends))
	for i, b := range upstreams.Backends {
		backends[i] = balancer.Backend{URL: b.URL, APIKey: b.APIKey}
	}
	return balancer.New(balancer.Config{
		Backends: backends,
		HealthCheck: balancer.HealthCheckConfig{
			Interval: upstreams.HealthCheck.Interval,
			Timeout:  upstreams.HealthCheck.Timeout,
			Path:     upstreams.HealthCheck.Path,
		},
	})
}

func openPluginManager(cfg *config.Config) (*authzplugin.Manager, error) {
	if len(cfg.Plugins) == 0 {
		return nil, fmt.Errorf("no plugins configured: at least one authorization plugin is required")
	}

	// Resolve plugin configs with defaults applied.
	plugins := make(map[string]authz.PluginConfig, len(cfg.Plugins))
	for name := range cfg.Plugins {
		pc, err := cfg.PluginConfigResolved(name)
		if err != nil {
			return nil, fmt.Errorf("resolve plugin %q config: %w", name, err)
		}
		plugins[name] = authz.PluginConfig{
			Path:             pc.Path,
			SHA256:           pc.SHA256,
			Timeout:          pc.Timeout,
			FailureThreshold: pc.CircuitBreaker.FailureThreshold,
			SuccessThreshold: pc.CircuitBreaker.SuccessThreshold,
			Cooldown:         pc.CircuitBreaker.Cooldown,
		}
	}

	mgr, err := authzplugin.NewManager(plugins)
	if err != nil {
		return nil, fmt.Errorf("start plugin manager: %w", err)
	}
	slog.Info("authorization plugins loaded", "count", len(plugins))
	return mgr, nil
}

func newProxyServer(listenAddr string, maxBodySize int64, auditOpts audit.Options, rl ratelimit.RateLimiter, lb proxy.Backend, keyStore store.KeyStore, auditPub audit.Publisher, pluginMgr *authzplugin.Manager, authnService authn.Service, resolver *clientip.Resolver) *http.Server {
	handler := middleware.Chain(
		middleware.RequestID,
		metrics.Middleware,
		tracing.Middleware,
		audit.Middleware(auditPub, auditOpts, resolver),
		hmac.Middleware(keyStore, authnService, resolver),
		ratelimit.Middleware(rl),
		middleware.BodyBuffer(maxBodySize),
		authz.Middleware(pluginMgr),
	)(lb)

	// Health probes get request ID and metrics but skip auth/authz.
	probeChain := middleware.Chain(
		middleware.RequestID,
		metrics.Middleware,
	)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.Handle("GET /healthz", probeChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})))
	mux.Handle("GET /readyz", probeChain(readinessCheck(keyStore, pluginMgr, lb)))

	return &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func newAdminServer(listenAddr, adminToken string, keygen admin.KeyGenerator, keyStore store.KeyStore) *http.Server {
	if adminToken == "" {
		return nil
	}

	keyMgr, ok := keyStore.(store.KeyManager)
	if !ok {
		slog.Warn("admin API requires a database-backed key store, skipping")
		return nil
	}

	slog.Info("admin API enabled", "listen", listenAddr)
	return admin.NewServer(listenAddr, keyMgr, keygen, adminToken)
}

func readinessCheck(ks store.KeyStore, pluginMgr *authzplugin.Manager, lb proxy.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := ks.GetByID(r.Context(), "__healthcheck__"); err != nil {
			http.Error(w, "store unhealthy", http.StatusServiceUnavailable)
			return
		}
		if !pluginMgr.Healthy() {
			http.Error(w, "no healthy plugins", http.StatusServiceUnavailable)
			return
		}
		if !lb.Healthy() {
			http.Error(w, "no healthy backends", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// ── Signal handling & server lifecycle ───────────────────────────────

func handleSIGHUP(reopenFn func() error, done <-chan struct{}) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	for {
		select {
		case <-done:
			return
		case <-sighup:
			metrics.SighupTotal.Inc()
			slog.Info("received SIGHUP, reopening audit log")
			if err := reopenFn(); err != nil {
				slog.Error("reopen audit log", "error", err)
			}
		}
	}
}

// runKeyCleanup periodically deletes expired keys from the store.
func runKeyCleanup(ctx context.Context, interval time.Duration, mgr store.KeyManager) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := mgr.DeleteExpired(ctx, time.Now())
			if err != nil {
				slog.Error("auto key cleanup failed", "error", err)
				continue
			}
			if n > 0 {
				slog.Info("auto key cleanup completed", "deleted", n)
				if auditErr := mgr.AuditKeyEvent(ctx, "", "auto_cleanup", "system", nil,
					map[string]any{"deleted": n}); auditErr != nil {
					slog.Error("audit auto cleanup", "error", auditErr)
				}
			}
		}
	}
}

func listenAndServe(ctx context.Context, shutdownWait time.Duration, proxySrv, metricsSrv, adminSrv *http.Server) error {
	errCh := make(chan error, 3)
	go func() {
		if err := proxySrv.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("proxy server: %w", err)
		}
	}()

	go func() {
		if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	if adminSrv != nil {
		go func() {
			if err := adminSrv.ListenAndServe(); err != http.ErrServerClosed {
				errCh <- fmt.Errorf("admin server: %w", err)
			}
		}()
	}

	slog.Info("server ready",
		"proxy", proxySrv.Addr,
		"metrics", metricsSrv.Addr,
		"admin", func() string {
			if adminSrv != nil {
				return adminSrv.Addr
			}
			return "disabled"
		}())

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down", "timeout", shutdownWait)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownWait)
		defer cancel()

		if adminSrv != nil {
			if err := adminSrv.Shutdown(shutdownCtx); err != nil {
				slog.Error("admin server shutdown", "error", err)
			}
		}
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("metrics server shutdown", "error", err)
		}
		if err := proxySrv.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}

	slog.Info("server stopped")
	return nil
}
