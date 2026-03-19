package balancer

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mai/pdag/internal/metrics"
)

// healthLoop periodically checks each backend's health endpoint.
func (lb *Balancer) healthLoop(ctx context.Context, cfg HealthCheckConfig) {
	defer lb.wg.Done()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: cfg.Timeout}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lb.checkAll(ctx, client, cfg)
		}
	}
}

func (lb *Balancer) checkAll(ctx context.Context, client *http.Client, cfg HealthCheckConfig) {
	var wg sync.WaitGroup
	for i := range lb.backends {
		wg.Add(1)
		go func(entry *backendEntry) {
			defer wg.Done()
			lb.checkOne(ctx, client, entry, cfg)
		}(&lb.backends[i])
	}
	wg.Wait()
}

func (lb *Balancer) checkOne(ctx context.Context, client *http.Client, entry *backendEntry, cfg HealthCheckConfig) {
	wasHealthy := entry.healthy.Load()

	// Use a per-check timeout so one slow backend doesn't block others.
	checkCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, "GET", entry.url+cfg.Path, nil)
	if err != nil {
		slog.Error("health check request creation failed", "backend", entry.url, "error", err)
		return
	}
	req.Header.Set("X-API-Key", entry.apiKey)

	resp, err := client.Do(req)
	healthy := err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300
	if resp != nil {
		resp.Body.Close()
	}

	entry.healthy.Store(healthy)

	val := float64(0)
	if healthy {
		val = 1
	}
	metrics.UpstreamBackendHealthy.WithLabelValues(entry.url).Set(val)

	if wasHealthy && !healthy {
		slog.Warn("backend became unhealthy", "backend", entry.url, "error", err)
	} else if !wasHealthy && healthy {
		slog.Info("backend recovered", "backend", entry.url)
	}
}
