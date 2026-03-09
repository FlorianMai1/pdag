package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP request metrics
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "http_requests_total",
		Help:      "Total HTTP requests processed.",
	}, []string{"method", "path_pattern", "status_code"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pdag",
		Name:      "http_request_duration_seconds",
		Help:      "End-to-end request latency.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path_pattern", "status_code"})

	HTTPRequestBodyBytes = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pdag",
		Name:      "http_request_body_bytes",
		Help:      "Request body size in bytes.",
		Buckets:   prometheus.ExponentialBuckets(64, 4, 8), // 64, 256, 1K, 4K, 16K, 64K, 256K, 1M
	}, []string{"method"})

	HTTPActiveRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "pdag",
		Name:      "http_active_requests",
		Help:      "Currently in-flight requests.",
	})

	// Authentication metrics
	AuthnTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "authn_total",
		Help:      "Authentication outcomes.",
	}, []string{"result"})

	KeyStoreQueryDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pdag",
		Name:      "keystore_query_duration_seconds",
		Help:      "KeyStore GetByID latency.",
		Buckets:   prometheus.DefBuckets,
	})

	KeyStoreErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "keystore_errors_total",
		Help:      "KeyStore query errors.",
	})

	// Authorization / Plugin metrics
	AuthzDecisionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "authz_decision_total",
		Help:      "Per-plugin authorization outcomes.",
	}, []string{"plugin", "decision"})

	AuthzPluginDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pdag",
		Name:      "authz_plugin_duration_seconds",
		Help:      "Per-plugin gRPC call latency.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"plugin"})

	AuthzCircuitBreakerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pdag",
		Name:      "authz_circuit_breaker_state",
		Help:      "Circuit breaker state: 0=closed, 1=half-open, 2=open.",
	}, []string{"plugin"})

	AuthzCircuitBreakerTransitions = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "authz_circuit_breaker_transitions_total",
		Help:      "Circuit breaker state transitions.",
	}, []string{"plugin", "from", "to"})

	// Rate limiting metrics
	RateLimitedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "rate_limited_total",
		Help:      "Requests rejected by rate limiting.",
	}, []string{"principal"})

	// Audit metrics
	AuditWriteErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "audit_write_errors_total",
		Help:      "Audit log write failures.",
	})

	// Upstream metrics
	UpstreamBackendHealthy = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pdag",
		Name:      "upstream_backend_healthy",
		Help:      "Whether upstream backend is healthy (1=yes, 0=no).",
	}, []string{"backend"})

	UpstreamRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pdag",
		Name:      "upstream_request_duration_seconds",
		Help:      "Latency of proxied calls to pdAPI.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "status_code"})

	UpstreamErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pdag",
		Name:      "upstream_errors_total",
		Help:      "Upstream connection failures.",
	}, []string{"reason"})
)
