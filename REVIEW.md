# PDAG Code Review: Bugs & Design Issues

## Bugs

### 1. Plugin restart never clears `restarting` flag on success — ADDRESSED

**File:** `internal/authz/plugin/manager.go`

When `restartPlugin` succeeds, it replaces the plugin instance in the map but never sets `restarting.Store(false)` on the **new** instance. The old instance's flag is irrelevant since it's been replaced. This means if the new instance later crashes, `inst.restarting.CompareAndSwap(false, true)` at line 208 will check the **new** instance (which defaults to `false`), so it actually works by accident.

However, if all 5 restart attempts fail, line 267-269 reads back from the map, but the instance in the map is still the **old crashed** one with `restarting=true`. It correctly resets it, but then the old crashed client will keep getting `callPlugin` invocations that always fail (the client has exited), triggering another restart loop endlessly.

**Fix:** Added a `failed atomic.Bool` field to `pluginInstance`. When all restart attempts are exhausted, the plugin is marked `failed`. `callPlugin` checks this flag early and returns an instant deny without attempting gRPC or triggering further restarts. The restart guard condition also checks `!inst.failed.Load()` before `CompareAndSwap`.

### 2. Double `StatusRecorder` wrapping — ADDRESSED

**Files:** `internal/audit/middleware.go` + `internal/metrics/middleware.go` + `internal/middleware/context.go`

Both the audit middleware and metrics middleware wrap `w` in a `StatusRecorder`. The middleware chain is `Metrics -> Audit -> ...`, so metrics wraps first, then audit wraps the already-wrapped writer. The metrics middleware reads `rec.StatusCode` from its own recorder, but since audit's recorder is what downstream handlers actually write to, the metrics recorder's `WriteHeader` is called by audit's recorder (via the embedded `ResponseWriter`). This actually works due to the embedding chain, but it means `WriteHeader` is called twice on the metrics recorder if downstream calls it explicitly -- once from the audit recorder forwarding, and the metrics recorder stores it. Not a correctness bug per se, but wasteful double-wrapping that could cause subtle issues with `http.Flusher`/`http.Hijacker` interface assertions.

**Fix:** Applied the existing pointer-in-context pattern (like `bodySizePtr` and `authzResultPtr`). Added `WithStatusCodePtr`/`GetStatusCodePtr` to the context helpers. The metrics middleware (outer) creates the single `StatusRecorder` and stores `&rec.StatusCode` in context. The audit middleware (inner) no longer wraps its own recorder — it reads the status code from the context pointer after the response completes.

### 3. `StatusRecorder` doesn't implement `http.Flusher` or `http.Hijacker` — ADDRESSED

**File:** `internal/middleware/statusrecorder.go`

`httputil.ReverseProxy` checks if the downstream `ResponseWriter` implements `http.Flusher` for streaming responses. Since `StatusRecorder` only embeds `http.ResponseWriter`, the interface is lost. This means **chunked/streaming responses from PowerDNS will be fully buffered** instead of streamed, increasing latency and memory usage for large zone transfers.

**Fix:** Added an `Unwrap() http.ResponseWriter` method to `StatusRecorder`. Since Go 1.20, `http.ResponseController` (used internally by `httputil.ReverseProxy`) calls `Unwrap()` to reach the underlying writer's optional interfaces (`http.Flusher`, `http.Hijacker`). This restores streaming support without manually implementing every optional interface.

### 4. Health check uses shutdown context — ADDRESSED

**File:** `internal/proxy/balancer/health.go`

`checkAll` passes the balancer's `ctx` (which is cancelled on `Close()`) to `http.NewRequestWithContext`. During graceful shutdown, `Close()` cancels the context, which is correct. But during normal operation if a single health check is slow, **all backends share the same sequential loop** -- a slow/hanging backend blocks health checks for subsequent backends until the HTTP client timeout (2s default) expires.

**Fix:** Refactored `checkAll` to run health checks concurrently (one goroutine per backend via `sync.WaitGroup`). Each check uses its own `context.WithTimeout` derived from the parent context, so a slow backend no longer blocks checks for other backends.

### 5. Audit log data loss on graceful shutdown — ADDRESSED

**File:** `internal/audit/file/logger.go`

`Close()` calls `close(l.ch)` then waits for `flushLoop` to finish. But if a `Publish()` call happens concurrently with `Close()` (which is possible since the proxy server is shutting down and may still be handling in-flight requests), it will **panic with "send on closed channel."**

**Fix:** Replaced the atomic flag approach (which had a TOCTOU race) with a `sync.RWMutex`-guarded `closed` bool. `Publish` holds an RLock during the channel send — many concurrent publishers can proceed without contention. `Close` takes the write lock, sets `closed=true`, then releases. After that, no new sends can reach the channel, so it's safe to signal the flush loop via a separate `stop` channel (the entry channel is never closed). The flush loop drains remaining buffered entries before exiting. Verified clean with `-race`.

### 6. `healthz` endpoint bypasses auth but not the middleware chain — ADDRESSED

**File:** `cmd/pdag/serve.go`

The `/healthz` and `/readyz` endpoints are registered on the same `mux` as the proxied handler, but the proxied handler is registered at `/`. Since Go 1.22's ServeMux uses most-specific-match, `/healthz` will match the `HandleFunc` directly. The healthz handler is **not wrapped in the middleware chain**, so it won't generate request IDs, metrics, or audit entries -- probably intentional but inconsistent. `/healthz` is accessible without authentication, which is fine for health checks but should be documented.

**Fix:** Wrapped `/healthz` and `/readyz` in a `probeChain` that applies `RequestID` and `Metrics` middleware (but intentionally skips auth/authz/audit). Health probes now get tracked in Prometheus and have request IDs, while remaining unauthenticated as expected for Kubernetes probes.

### 7. Readiness check doesn't test plugin *communication* — ADDRESSED

**File:** `cmd/pdag/serve.go` + `internal/authz/plugin/manager.go`

`pluginMgr.HasPlugins()` only checks `len(m.plugins) > 0` -- it doesn't verify that plugin processes are alive or responsive. A crashed plugin would still be "in the map" and `HasPlugins()` returns true, making the readiness check pass even when all plugins are dead.

**Fix:** Added `Healthy()` method to the plugin `Manager` that iterates all plugin instances and returns true only if at least one is not permanently failed and has a running process (`!inst.failed.Load() && !inst.client.Exited()`). The readiness check now calls `pluginMgr.Healthy()` instead of `HasPlugins()`.

## Design Issues

### 8. Global mutex contention on the plugin manager — ADDRESSED

**File:** `internal/authz/plugin/manager.go`

`Authorize` takes `m.mu.RLock()` for the entire duration of the fan-out -- including waiting for all plugin gRPC responses (up to 500ms default). Under high concurrency, a plugin restart (which takes `m.mu.Lock()` at line 249) will block **all** in-flight authorization requests until the restart completes. This could cause a latency spike affecting all principals, not just those using the restarting plugin.

**Fix:** Replaced `sync.RWMutex` + `map[string]*pluginInstance` with `atomic.Pointer[pluginMap]` using copy-on-write. The hot path (`Authorize`, `Healthy`, `HasPlugins`) is now completely lock-free — just an atomic pointer load to get an immutable snapshot. Writers (`restartPlugin`, `Close`) serialize via a separate `sync.Mutex` and perform copy-on-write: load current map → copy → modify → atomic store. An `atomic.Bool` `closed` flag prevents `restartPlugin` from re-adding a plugin after `Close` has emptied the map.

### 9. Admin API has no rate limiting or request size limits — ADDRESSED

**File:** `internal/admin/server.go`

The admin API server has no middleware for rate limiting, body size limits, or request timeouts. A malicious actor with the admin token (or during a brute-force attempt) could send unlimited requests or very large JSON bodies to `POST /admin/keys`. The `json.NewDecoder(r.Body).Decode` will read unbounded input.

**Fix:** Added three protections: (1) `http.MaxBytesReader` wrapping limits request bodies to 64 KiB — oversized payloads are rejected before JSON decoding. (2) Per-IP token bucket rate limiter (10 req/s, burst 50) reusing the existing `ratelimit/token` package. (3) Server timeouts (`ReadHeaderTimeout: 5s`, `ReadTimeout: 10s`, `WriteTimeout: 30s`, `IdleTimeout: 60s`) to prevent slowloris and hung connections.

### 10. Admin token comparison leaks token length — ADDRESSED

**File:** `internal/admin/server.go`

`subtle.ConstantTimeCompare` is constant-time only when both inputs are the same length. When they differ in length, it returns 0 immediately. An attacker could determine the admin token length by measuring response times. Consider padding or using HMAC comparison instead.

**Fix:** Replaced direct byte comparison with HMAC-SHA256 comparison. Both the expected token and the candidate are HMACed with the same key, producing fixed-length 32-byte MACs. `subtle.ConstantTimeCompare` on equal-length MACs is truly constant-time regardless of input lengths. The expected token's MAC is precomputed at init time to avoid redundant hashing per request.

### 11. Missing `Accept` header forwarding on proxy — ADDRESSED

**File:** `internal/proxy/single/single.go` + `internal/proxy/balancer/balancer.go`

The header stripping removes **all** client headers, including `Accept`. PowerDNS API may return different representations based on `Accept`. More critically, `Authorization` headers from other middleware patterns are also stripped -- which is correct for PDAG's use case but means the proxy is not transparent in a broader sense.

**Fix:** Added `Accept` to the set of preserved headers in both proxy implementations (`single` and `balancer`). The header is saved before stripping and restored on the outbound request, matching the existing pattern for `Content-Type` and `Content-Length`.

### 12. `letsencrypt_dns_challenger` does synchronous DNS lookups in the hot path — ADDRESSED

**File:** `plugins/letsencrypt_dns_challenger/main.go`

`net.LookupHost` and `net.LookupCNAME` use the system resolver and can take seconds if DNS is slow. This runs within the plugin's 500ms default timeout, but the plugin has no internal context/timeout for the DNS lookup itself. A slow DNS resolver could cause the plugin to consistently time out, trip the circuit breaker, and deny all ACME challenges even when DNS eventually resolves.

**Fix:** Replaced package-level `net.LookupHost`/`net.LookupCNAME` with context-aware `net.Resolver` methods. Each DNS lookup now gets a 200ms timeout derived from the parent gRPC context, leaving headroom within the 500ms plugin timeout for multiple RRsets. The `Authorize` method now uses the incoming `context.Context` instead of discarding it.

### 13. Token bucket rate limiter holds global mutex for all principals — ADDRESSED

**File:** `internal/ratelimit/token/limiter.go`

All `Allow()` calls contend on a single `sync.Mutex`. Under high concurrency with many principals, this becomes a bottleneck. A `sync.Map` or sharded map would scale better.

**Fix:** Replaced the global `sync.Mutex` + `map[string]*bucket` with `sync.Map` + per-bucket `sync.Mutex`. Different principals never contend. The call counter uses `atomic.Int64` instead of a mutex-guarded int. Cleanup uses `sync.Map.Range` with per-bucket lock checks for staleness.

### 14. Audit log entry records `start` time as `Timestamp` — ADDRESSED

**File:** `internal/audit/middleware.go`

The entry timestamp is `start.UTC()` -- the time the request *began*, not when the audit entry was created. This is a design choice, not a bug, but it means the audit log timestamp doesn't reflect when the action completed. For compliance/forensics, the completion time is often more relevant.

**Fix:** Changed `Timestamp` from `start.UTC()` to `time.Now().UTC()`, reflecting when the response completed and the audit entry was created. The start time is still derivable as `timestamp - latency_ms`.

### 15. No pagination on `GET /admin/keys` — ADDRESSED

**File:** `internal/admin/server.go:149-173`

`List()` fetches all keys from the database with no pagination. With thousands of keys, this could be slow and memory-intensive.

**Fix:** Added `ListPaged(ctx, limit, offset)` to the `KeyManager` interface with implementations in both postgres (SQL `LIMIT/OFFSET`) and memory (sort by `CreatedAt` then slice) stores. The `GET /admin/keys` handler now parses `?limit=N&offset=N` query parameters with a default limit of 100 and a maximum of 1000. Invalid or missing values fall back to defaults.

### 16. Circuit breaker `Allow()` in half-open state allows unbounded concurrent calls

**File:** `internal/authz/plugin/circuitbreaker.go:77`

In `StateHalfOpen`, every call is allowed through. The typical circuit breaker pattern only allows a single "probe" request in half-open. Here, if many concurrent requests arrive during half-open, they all go through -- which could overwhelm a recovering plugin.

## Impact Summary

Most impactful issues:
- **#3**: Missing `Flusher` interface breaks streaming responses through the reverse proxy
- **#5**: Panic on concurrent `Publish`/`Close` during shutdown
- **#8**: RLock held during full plugin fan-out blocks restarts and causes latency spikes
- **#10**: Admin token length leakage via timing
- **#16**: Half-open circuit breaker doesn't limit concurrent probes

The codebase is well-structured overall -- clean separation of concerns, good use of interfaces, sensible defaults, and solid middleware composition. The plugin architecture via go-plugin is a strong choice for isolation. The main areas for improvement are around edge cases in concurrent shutdown paths and the circuit breaker implementation.
