# PDAG Code Review: Iteration 2

## 1. Config validation gaps — ADDRESSED

**File:** `internal/config/config.go`

Listen addresses, MaxBodySize, HMAC secret length, circuit breaker thresholds, plugin timeouts, rate limit values, health check intervals, and DB DSN are not validated. Invalid values (zero, negative, nonsensical combinations) silently produce broken runtime behavior instead of failing fast at startup.

**Fix:** Added validation in `validate()` for: listen addresses via `net.SplitHostPort`, `MaxBodySize > 0`, HMAC secrets >= 16 bytes, circuit breaker thresholds >= 0 (both defaults and per-plugin), `PluginDefaults.Timeout > 0`, rate limit `Rate > 0` and `Burst > 0` when enabled, health check `Timeout < Interval` for multi-backend configs, and non-empty DSN when driver is postgres. Port conflicts produce a warning via `slog.Warn`.

## 2. Expired keys accumulate in the database — ADDRESSED

**File:** `internal/store/store.go`, `internal/admin/server.go`

Expired keys are correctly rejected at request time but remain in the database forever. No admin endpoint or mechanism exists to purge them. Over time this bloats the store and slows paginated queries.

**Fix:** Added `DELETE /admin/keys/expired` endpoint that calls `DeleteExpired(ctx, time.Now())` on the store. Returns `{"deleted": N}`. Operators wire this to an external cron if they want periodic cleanup — no background magic. Added `DeleteExpired` to `KeyManager` interface with postgres and memory implementations, plus a partial index on `expires_at` (migration 002).

## 3. No `GET /admin/keys/{id}` endpoint

**File:** `internal/admin/server.go`

The admin API supports listing all keys with pagination but has no endpoint to retrieve a single key by ID. Operators must page through the full list to find a specific key's details.

## 4. No key filtering by principal or role

**File:** `internal/admin/server.go`

`GET /admin/keys` only supports `limit` and `offset`. There is no `?principal=X` or `?role=Y` filter. Operators managing many keys must fetch everything client-side.

## 5. Graceful shutdown doesn't check admin server error

**File:** `cmd/pdag/serve.go`

The proxy server shutdown checks errors and passes a timeout context. The admin server shutdown has neither — its error is silently discarded and it uses a background context with no deadline.

## 6. No `pdag config validate` subcommand

**File:** `cmd/pdag/main.go`

There is no way to validate a config file without starting the server. Operators deploying via CI/CD must start the full server to discover config errors.

## 7. Metrics gaps

**Files:** `internal/metrics/metrics.go`, `internal/audit/file/logger.go`

No metrics for: audit log queue depth/dropped entries, DB connection pool health, SIGHUP config reload events, or body buffer sizes.

## 8. Plugin binary hash not enforced

**File:** `internal/config/config.go`, `internal/authz/plugin/manager.go`

Plugin binary hashes are logged at startup but a modified binary loads without error. An operator has no way to detect tampering without checking logs.

## 9. No key expiry update endpoint

**File:** `internal/admin/server.go`

Once created, a key's `expires_at` cannot be changed. Extending or shortening a key's lifetime requires deleting and recreating it, which changes the key ID and secret.

## 10. No OpenTelemetry / distributed tracing

The gateway supports Prometheus metrics but has no tracing. Debugging slow plugin fan-out or upstream latency requires correlating logs manually across request IDs.

## 11. No Makefile or CI pipeline

There is no build automation, linting config (`.golangci.yml`), or CI workflow (`.github/workflows/`). Tests and builds are run manually.

## 12. No Kubernetes manifests or Helm chart

Only `docker-compose.yml` exists. Production deployment to Kubernetes requires writing manifests from scratch.
