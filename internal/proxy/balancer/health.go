package balancer

import (
	"context"
	"log/slog"
	"net/http"
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
			lb.checkAll(ctx, client, cfg.Path)
		}
	}
}

func (lb *Balancer) checkAll(ctx context.Context, client *http.Client, path string) {
	for i := range lb.backends {
		entry := &lb.backends[i]
		wasHealthy := entry.healthy.Load()

		req, err := http.NewRequestWithContext(ctx, "GET", entry.url+path, nil)
		if err != nil {
			continue
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
}
