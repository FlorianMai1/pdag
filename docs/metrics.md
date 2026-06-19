# Metrics Catalog

PDAG exposes Prometheus metrics on the **metrics server** (`:9090` by default) at
`GET /metrics`. The same server also serves `GET /healthz` (always `200 ok`, for
liveness). All metric names use the `pdag_` namespace prefix.

For where this server sits relative to the proxy (`:8080`) and admin (`:9091`)
servers, see [`architecture.md`](architecture.md).

> [!WARNING]
> **The `/metrics` endpoint is unauthenticated.** It exposes operational detail
> (plugin names, backend names, queue depths, error counts) that should not be
> public. Bind the metrics server to an internal interface and/or restrict it at
> the network layer (firewall, internal-only listener, scrape from a trusted
> Prometheus only). Never expose `:9090` to the internet.

Histograms additionally export `_count` and `_sum` series plus one `_bucket`
series per bucket boundary; `prometheus.DefBuckets` is the client-default set.

---

## HTTP / proxy

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_http_requests_total` | counter | `method`, `path_pattern`, `status_code` | Total HTTP requests processed. |
| `pdag_http_request_duration_seconds` | histogram (DefBuckets) | `method`, `path_pattern`, `status_code` | End-to-end request latency. |
| `pdag_http_request_body_bytes` | histogram (exp: 64,256,1K,4K,16K,64K,256K,1M) | `method` | Request body size in bytes. |
| `pdag_http_active_requests` | gauge | — | Currently in-flight requests. |

## Authentication (authn)

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_authn_total` | counter | `result` | Authentication outcomes. |
| `pdag_keystore_query_duration_seconds` | histogram (DefBuckets) | — | KeyStore GetByID latency. |
| `pdag_keystore_errors_total` | counter | — | KeyStore query errors. |

## Authorization / circuit breaker (authz)

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_authz_decision_total` | counter | `plugin`, `decision` | Per-plugin authorization outcomes. |
| `pdag_authz_plugin_duration_seconds` | histogram (DefBuckets) | `plugin` | Per-plugin gRPC call latency. |
| `pdag_authz_circuit_breaker_state` | gauge | `plugin` | Circuit breaker state: 0=closed, 1=half-open, 2=open. |
| `pdag_authz_circuit_breaker_transitions_total` | counter | `plugin`, `from`, `to` | Circuit breaker state transitions. |

`plugin` corresponds 1:1 to a role/plugin name from the `plugins:` config block;
`decision` reflects the proto `Decision` (`ALLOW`/`DENY`). See
[`design_decisions.md`](design_decisions.md) for the first-ALLOW-wins evaluation
model.

## Rate limiting

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_rate_limited_total` | counter | — | Requests rejected by rate limiting. |

Intentionally aggregate (no per-principal label) to keep cardinality bounded.

## Audit

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_audit_write_errors_total` | counter | — | Audit log write failures. |
| `pdag_audit_queue_depth` | gauge | — | Current number of entries buffered in the audit log channel. |
| `pdag_audit_dropped_total` | counter | — | Audit log entries dropped due to full buffer or closed logger. |
| `pdag_audit_reopen_failures_total` | counter | — | Audit log reopen (SIGHUP) failures; the previous file is kept so no entries are lost. |
| `pdag_audit_inconsistency_total` | counter | — | Admin key mutations applied but not audited (audit write failed after the mutation committed); requires operator reconciliation. |

## Upstream (pdAPI)

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_upstream_backend_healthy` | gauge | `backend` | Whether upstream backend is healthy (1=yes, 0=no). |
| `pdag_upstream_request_duration_seconds` | histogram (DefBuckets) | `method`, `status_code` | Latency of proxied calls to pdAPI. |
| `pdag_upstream_errors_total` | counter | `reason` | Upstream connection failures. |

## Operational

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_sighup_total` | counter | — | Number of SIGHUP signals received. |

## Database connection pool

Exported by a custom collector (`DBPoolCollector`) that reads `sql.DBStats` on
every scrape. These are only present when a DB DSN is configured (the in-memory
store is dev-only and registers no pool collector).

| Metric | Type | Labels | Help |
| --- | --- | --- | --- |
| `pdag_db_pool_open_connections` | gauge | — | Number of open connections to the database. |
| `pdag_db_pool_idle_connections` | gauge | — | Number of idle connections in the pool. |
| `pdag_db_pool_in_use_connections` | gauge | — | Number of connections currently in use. |
| `pdag_db_pool_wait_count_total` | counter | — | Total number of connections waited for. |

---

## Suggested alerts

These cover the security- and availability-critical signals. Tune thresholds,
`for:` durations, and label matchers to your deployment.

### Audit integrity (security-critical)

Any nonzero value here means audit coverage was lost. Audit is the core purpose
of PDAG, so these should page.

```yaml
# Entries dropped (full buffer or closed logger) — audit trail has gaps.
- alert: PDAGAuditDropped
  expr: increase(pdag_audit_dropped_total[5m]) > 0
  for: 0m
  labels: { severity: critical }
  annotations:
    summary: "PDAG dropped audit log entries"

# Mutation committed upstream but not audited — needs manual reconciliation.
- alert: PDAGAuditInconsistency
  expr: increase(pdag_audit_inconsistency_total[5m]) > 0
  for: 0m
  labels: { severity: critical }
  annotations:
    summary: "PDAG admin mutation applied but not audited (reconcile required)"

# Log reopen (SIGHUP/rotation) failed — rotation pipeline broken.
- alert: PDAGAuditReopenFailures
  expr: increase(pdag_audit_reopen_failures_total[15m]) > 0
  for: 0m
  labels: { severity: warning }
  annotations:
    summary: "PDAG failed to reopen audit log on SIGHUP"

# Sustained write failures and/or backlog building up.
- alert: PDAGAuditWriteErrors
  expr: increase(pdag_audit_write_errors_total[5m]) > 0
  for: 5m
  labels: { severity: warning }
- alert: PDAGAuditQueueBacklog
  expr: pdag_audit_queue_depth > 0
  for: 10m
  labels: { severity: warning }
  annotations:
    summary: "PDAG audit queue not draining (writer may be stuck/slow)"
```

### Authz circuit breaker stuck open (availability-critical)

State `2` = open. A plugin stuck open means that role's requests fail their authz
path; sustained open usually indicates a crashed/unresponsive plugin.

```yaml
- alert: PDAGAuthzCircuitBreakerOpen
  expr: pdag_authz_circuit_breaker_state == 2
  for: 5m
  labels: { severity: critical }
  annotations:
    summary: "Authz circuit breaker stuck open for plugin {{ $labels.plugin }}"

# Flapping breaker (frequent transitions) — plugin is unstable.
- alert: PDAGAuthzCircuitBreakerFlapping
  expr: increase(pdag_authz_circuit_breaker_transitions_total[5m]) > 5
  for: 5m
  labels: { severity: warning }
```

### Upstream errors (availability)

```yaml
- alert: PDAGUpstreamErrors
  expr: sum(rate(pdag_upstream_errors_total[5m])) > 0.1
  for: 5m
  labels: { severity: critical }
  annotations:
    summary: "PDAG seeing upstream pdAPI errors ({{ $labels.reason }})"

- alert: PDAGUpstreamBackendDown
  expr: pdag_upstream_backend_healthy == 0
  for: 1m
  labels: { severity: critical }
  annotations:
    summary: "PDAG upstream backend {{ $labels.backend }} unhealthy"
```

### Rate limiting (capacity / abuse)

A nonzero, sustained reject rate may mean legitimate clients are throttled or an
abusive caller is hitting limits.

```yaml
- alert: PDAGRateLimiting
  expr: rate(pdag_rate_limited_total[5m]) > 1
  for: 10m
  labels: { severity: warning }
  annotations:
    summary: "PDAG is rejecting requests via rate limiting"
```

### Authn failures (security)

A spike in failed authentications can indicate credential stuffing or a broken
caller integration.

```yaml
- alert: PDAGAuthnFailureSpike
  expr: sum(rate(pdag_authn_total{result!="success"}[5m])) > 1
  for: 10m
  labels: { severity: warning }
```
