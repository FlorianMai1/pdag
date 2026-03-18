# PDAG Code Review: Iteration 2

## 1. Config validation gaps — ADDRESSED

**File:** `internal/config/config.go`

Listen addresses, MaxBodySize, HMAC secret length, circuit breaker thresholds, plugin timeouts, rate limit values, health check intervals, and DB DSN are not validated. Invalid values (zero, negative, nonsensical combinations) silently produce broken runtime behavior instead of failing fast at startup.

**Fix:** Added validation in `validate()` for: listen addresses via `net.SplitHostPort`, `MaxBodySize > 0`, HMAC secrets >= 16 bytes, circuit breaker thresholds >= 0 (both defaults and per-plugin), `PluginDefaults.Timeout > 0`, rate limit `Rate > 0` and `Burst > 0` when enabled, health check `Timeout < Interval` for multi-backend configs, and non-empty DSN when driver is postgres. Port conflicts produce a warning via `slog.Warn`.

## 2. Expired keys accumulate in the database — ADDRESSED

**File:** `internal/store/store.go`, `internal/admin/server.go`

Expired keys are correctly rejected at request time but remain in the database forever. No admin endpoint or mechanism exists to purge them. Over time this bloats the store and slows paginated queries.

**Fix:** Added `DELETE /admin/keys/expired` endpoint that calls `DeleteExpired(ctx, time.Now())` on the store. Returns `{"deleted": N}`. Operators wire this to an external cron if they want periodic cleanup — no background magic. Added `DeleteExpired` to `KeyManager` interface with postgres and memory implementations, plus a partial index on `expires_at` (migration 002).

## 3. No `GET /admin/keys/{id}` endpoint — ADDRESSED

**File:** `internal/admin/server.go`

The admin API supports listing all keys with pagination but has no endpoint to retrieve a single key by ID. Operators must page through the full list to find a specific key's details.

**Fix:** Added `GET /admin/keys/{id}` route with `getKey()` handler. Returns the key as JSON or 404 if not found.

## 4. No key filtering by principal or role — ADDRESSED

**File:** `internal/admin/server.go`

`GET /admin/keys` only supports `limit` and `offset`. There is no `?principal=X` or `?role=Y` filter. Operators managing many keys must fetch everything client-side.

**Fix:** Added `?principal=X&role=Y` query parameters to `GET /admin/keys`. Added `ListFiltered` to the `KeyManager` interface with postgres (dynamic WHERE clause) and memory implementations. When no filters are provided, behavior is identical to the previous `ListPaged`.

## 5. Graceful shutdown doesn't check admin server error — ADDRESSED

**File:** `cmd/pdag/serve.go`

The proxy server shutdown checks errors and passes a timeout context. The admin server shutdown has neither — its error is silently discarded and it uses a background context with no deadline.

**Fix:** Admin and metrics server shutdown errors are now logged via `slog.Error`.

## 6. No `pdag config validate` subcommand — ADDRESSED

**File:** `cmd/pdag/main.go`, `cmd/pdag/validate.go`

There is no way to validate a config file without starting the server. Operators deploying via CI/CD must start the full server to discover config errors.

**Fix:** Added `pdag validate --config <path>` subcommand that runs `config.Load()` and prints "config OK" on success.

## 7. Metrics gaps — ADDRESSED

**Files:** `internal/metrics/metrics.go`, `internal/metrics/dbpool.go`, `internal/audit/file/logger.go`, `cmd/pdag/serve.go`

No metrics for: audit log queue depth/dropped entries, DB connection pool health, SIGHUP config reload events, or body buffer sizes.

**Fix:** Added `pdag_audit_queue_depth` gauge (sampled on each Publish), `pdag_audit_dropped_total` counter, `pdag_sighup_total` counter, and `pdag_db_pool_*` metrics (open/idle/in_use connections, wait count) via a custom `prometheus.Collector` that reads `sql.DBStats` on each scrape.

## 8. Plugin binary hash not enforced — ADDRESSED

**File:** `internal/config/config.go`, `internal/authz/plugin/manager.go`, `internal/authz/authz.go`

Plugin binary hashes are logged at startup but a modified binary loads without error. An operator has no way to detect tampering without checking logs.

**Fix:** Added optional `sha256` field to plugin config. When set, the computed hash must match exactly or the plugin refuses to start. When unset, hash is logged but not enforced (backwards compatible). Config validation rejects non-64-char or non-hex values.

## 9. No key expiry update endpoint — ADDRESSED

**File:** `internal/admin/server.go`, `internal/store/store.go`

Once created, a key's `expires_at` cannot be changed. Extending or shortening a key's lifetime requires deleting and recreating it, which changes the key ID and secret.

**Fix:** Added `PATCH /admin/keys/{id}/expiry` endpoint accepting `{"expires_at": "RFC3339"}` or `{"expires_at": null}` to clear. Added `SetExpiresAt` to `KeyManager` interface with postgres and memory implementations.

## 10. No OpenTelemetry / distributed tracing — ADDRESSED

~~The gateway supports Prometheus metrics but has no tracing. Debugging slow plugin fan-out or upstream latency requires correlating logs manually across request IDs.~~

**Fix:** Added OpenTelemetry distributed tracing via OTLP gRPC exporter. Trace spans cover the full request lifecycle: root span (tracing middleware), authentication (HMAC middleware), and authorization fan-out (per-plugin child spans). Configurable via `tracing` section in config: endpoint, insecure mode, sample rate. When disabled (default), all spans are no-ops with zero overhead. W3C `traceparent` propagation is supported for end-to-end trace correlation.

## 11. No Makefile or CI pipeline — PARTIALLY ADDRESSED

~~There is no build automation, linting config (`.golangci.yml`), or CI workflow (`.github/workflows/`). Tests and builds are run manually.~~

**Fix:** Added `Makefile` with `make check` (fix, fmt, vet, lint, test), per-plugin build targets, integration test target, and proto regeneration. Added `.golangci.yml` with errorlint, bodyclose, sqlclosecheck, and other linters. CI workflow (`.github/workflows/`) is still missing.

## 12. No Kubernetes manifests or Helm chart

Only `docker-compose.yml` exists. Production deployment to Kubernetes requires writing manifests from scratch.
