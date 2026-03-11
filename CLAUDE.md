# PDAG — PowerDNS Audit Gateway

A lightweight, performant reverse proxy in Go that sits in front of the PowerDNS Authoritative API (pdAPI). It adds audit logging and role-based access control without modifying or redefining the upstream API.

## Problem

The PowerDNS API authenticates via a single static `X-API-Key` header. There is no concept of multiple users, roles, permissions, or audit trails. PDAG solves this by intercepting requests, authenticating callers with their own credentials, authorizing against plugin-based policies, logging every action, and forwarding permitted requests upstream with the real static API key.

## Architecture

```
Client → PDAG (auth + audit + authz) → PowerDNS API backend(s)
```

PDAG is a transparent reverse proxy. It does **not** rewrite, wrap, or redefine any pdAPI endpoint. Clients interact with the same PowerDNS API surface — the only change is the `X-API-Key` header value format:

```
X-API-Key: <apiKeyID>:<apiKey>
```

PDAG splits on the first `:`, resolves the key ID to a principal, validates the key, evaluates authorization, and — if allowed — replaces the header with the real upstream API key before proxying.

Three servers run independently: proxy (`:8080`), metrics (`:9090`), admin API (`:9091`).

## Key Design Decisions

### HMAC-SHA256 over argon2/bcrypt for key hashing

API keys are high-entropy machine-generated secrets (32+ random bytes), not user-chosen passwords. Brute-force is infeasible regardless of hash speed. HMAC-SHA256 keeps verification on the hot path cheap (sub-microsecond vs ~100ms for argon2). The HMAC secret lives in config/env, **not** in the database — a DB leak alone is insufficient to verify candidate keys.

### HMAC secret rotation

Each key row stores an `hmac_key_id` indicating which secret produced its hash. Config supports a list of HMAC secrets (first = current for new keys, rest = still accepted for verification). This allows rotating the HMAC secret without invalidating all keys at once.

### Plugin-based authorization over regex/method matching

Simple regex + method matching is not expressive enough. Roles often need to inspect the request body and make domain-aware decisions. For example, `letsencrypt_dns_challenger` must verify that a PATCH only touches TXT records with an `_acme-challenge.` prefix — and may resolve the FQDN to confirm an A/AAAA record exists.

**Each role is a standalone plugin binary** using [HashiCorp go-plugin](https://github.com/hashicorp/go-plugin) over gRPC:

- **Domain logic isolation** — each plugin is its own binary with its own dependencies. A crash does not bring down PDAG.
- **Independent deployability** — add or update a role by dropping a new binary. No PDAG recompile needed.
- **Full request introspection** — plugins receive method, path, headers, and the full buffered request body via protobuf (see `proto/authz/authz.proto`).

### Authorization flow: logical OR with fan-out

Plugins for all assigned roles are called **concurrently**. Any single `ALLOW` is sufficient — first ALLOW cancels remaining calls. If all return `DENY` (or none are assigned), return 403. Errors, timeouts, and circuit-broken plugins count as `DENY` for that plugin.

### Circuit breaker per plugin

A single misbehaving plugin must never degrade the entire gateway. Each plugin has a per-call timeout (default 500ms) and a per-plugin circuit breaker (closed → open → half-open). If a plugin's external dependency (e.g. DNS resolver) goes down, the circuit trips after a few failures and all subsequent requests get instant `DENY` — the gateway stays healthy for all other principals and roles. Configuration is per-plugin with global defaults (see `plugin_defaults` in config).

### Request body buffering (store-and-forward)

Request bodies are buffered into memory (up to `max_body_size`, default 1 MiB) before dispatching to plugins, then restored on `r.Body` for proxying. Requests exceeding the limit get 413.

### Header stripping on proxy

All client-supplied headers are stripped from the outbound request to prevent header injection into pdAPI. Only `X-API-Key` (real upstream key), `Host`, `Content-Type`, `Content-Length`, and `Accept` are set on the proxied request.

### Two separate log streams

- **Application log** (stderr, `slog`) — operational: startup, config reload, plugin lifecycle, circuit breaker transitions, errors. `SanitizeHeaders()` redacts `X-Api-Key` values before any log output.
- **Audit log** (dedicated JSON lines file) — one structured entry per request for compliance/forensics. Logged after proxying so the upstream status code is available. Reopened on SIGHUP for log rotation.

### Interface-at-boundary, implementation-in-subpackage

Every major internal component follows the same structure: the **parent package** defines the interface and any noop/test helpers; **subpackages** provide concrete implementations. The parent never imports its children — wiring happens in `cmd/pdag/serve.go`.

```
internal/store/store.go         → KeyStore (read), KeyManager (read+write) interfaces
internal/store/memory/           → in-memory impl (dev)
internal/store/postgres/         → PostgreSQL impl (prod)

internal/proxy/proxy.go         → Backend interface
internal/proxy/single/           → single upstream, always healthy
internal/proxy/balancer/         → round-robin with health checks

internal/audit/audit.go         → Publisher interface, Noop()
internal/audit/file/             → JSON-lines file impl

internal/authn/authn.go         → Service interface
internal/authn/hmac/             → HMAC-SHA256 impl

internal/authz/authz.go         → Authorizer interface
internal/authz/plugin/           → go-plugin gRPC fan-out impl

internal/ratelimit/ratelimit.go → RateLimiter interface, Noop()
internal/ratelimit/token/        → token bucket impl

internal/admin/admin.go         → KeyGenerator interface
internal/admin/hmac/             → HMAC key generator impl
```

This gives compile-time decoupling (middleware depends only on `store.KeyStore`, never on `postgres`), makes implementations swappable (memory store for tests, postgres for prod), and keeps each subpackage focused on one concern. When adding a new component, define the interface in the parent package first, then implement in a subpackage.

### Plugins are required

PDAG refuses to start without at least one authorization plugin configured. Without plugins, every request would be denied — failing fast at startup is better than silent 403s at runtime.

### Multi-backend load balancing

PDAG supports multiple upstream PowerDNS backends for high availability. Multiple pdns-auth instances safely share a single PostgreSQL database — the DB provides transactional consistency and PowerDNS has no local cache for API reads, so read-your-writes is guaranteed without replication lag concerns.

Config always uses the `upstreams.backends` list (there is no legacy singular `upstream` form). With a single backend, the `single` implementation is used (no health check goroutine). With multiple backends, the `balancer` uses lock-free round-robin (`atomic.Uint64` counter) with both active and passive health checking:

- **Active**: periodic HTTP GET to a configurable health endpoint per backend.
- **Passive**: `ErrorHandler` on each reverse proxy marks a backend unhealthy on transport errors (connection refused, timeout).

The `proxy.Backend` interface is defined in `internal/proxy/proxy.go`. Implementations live in subpackages: `internal/proxy/single` (single backend, always healthy) and `internal/proxy/balancer` (round-robin with health checks). `cmd/pdag/serve.go` selects the implementation based on the number of configured backends.

### Fail fast on invalid config

PDAG validates all configuration at startup and refuses to start if anything is invalid. This includes listen address format, `MaxBodySize > 0`, HMAC secret minimum length (16 bytes), circuit breaker thresholds, rate limit values when enabled, health check `timeout < interval` for multi-backend setups, and non-empty DSN when using postgres. Port conflicts between proxy/metrics/admin produce a warning. The principle: a bad config should be caught at deploy time, not as a mysterious runtime failure.

### No background cleanup — operator-driven operations

PDAG does not run background jobs for housekeeping (e.g., purging expired keys, rotating secrets). Instead, it exposes explicit admin API endpoints (`DELETE /admin/keys/expired`) that operators call on their own schedule — via cron, CI/CD, or manual invocation. This keeps PDAG's behavior fully predictable: it does exactly what it's told, when it's told, with no hidden timers or implicit state changes.

### Constant-time admin token comparison

The admin API authenticates via a static bearer token. To prevent timing attacks that could leak the token length, both the expected and candidate tokens are HMAC-SHA256'd (producing fixed-length 32-byte MACs) before `subtle.ConstantTimeCompare`. The expected token's MAC is precomputed at init time.

### Lock-free hot path in plugin manager

The plugin manager uses `atomic.Pointer[pluginMap]` with copy-on-write for the plugin instance map. The hot path (`Authorize`, `Healthy`, `HasPlugins`) performs a single atomic pointer load — no mutexes, no contention. Writers (`restartPlugin`, `Close`) serialize via a separate `sync.Mutex` and perform copy-on-write: load → copy → modify → atomic store.

### Single StatusRecorder with Unwrap

Only the metrics middleware wraps the `ResponseWriter` in a `StatusRecorder`. The audit middleware reads the status code via a shared pointer in context (`WithStatusCodePtr`/`GetStatusCodePtr`), avoiding double-wrapping. `StatusRecorder` implements `Unwrap() http.ResponseWriter` so Go 1.20+'s `http.ResponseController` can reach the underlying writer's `http.Flusher`/`http.Hijacker` interfaces for streaming support.

### Circuit breaker half-open limits concurrency

In half-open state, only one "probe" request passes through at a time. A `halfOpenAllowed` bool flag is consumed by `Allow()` and re-enabled by `RecordSuccess()`, allowing sequential probes until `successThreshold` is met. This prevents a flood of requests from overwhelming a recovering plugin.

### No panic recovery middleware

Go's `net/http` server already recovers panics per-request. Plugins run out-of-process via go-plugin, so a plugin crash cannot bring down the proxy. Custom panic recovery adds complexity with no benefit.

## Middleware Chain

```
RequestID → Metrics → AuditLog → Authn → RateLimit → BodyBuffer → Authz → ReverseProxy
```

Each middleware is a `func(http.Handler) http.Handler`. Body buffering runs **after** authn so unauthenticated requests never pay the copy cost. Rate limiting runs after authn so it can bucket by principal.

## Admin API

The admin API runs on a separate server (`:9091`) protected by a static bearer token with per-IP rate limiting (10 req/s, burst 50) and 64 KiB body limits.

```
POST   /admin/keys                → Create key (returns ID + secret)
GET    /admin/keys?limit=N&offset=N → List keys (paginated, default 100, max 1000)
DELETE /admin/keys/expired         → Purge all expired keys (returns {"deleted": N})
DELETE /admin/keys/{id}            → Delete key
PATCH  /admin/keys/{id}/enable     → Enable key
PATCH  /admin/keys/{id}/disable    → Disable key
PUT    /admin/keys/{id}/roles      → Update roles
```

All mutating endpoints log to the `api_keys_audit` table with action, timestamp, and changed values.

## Non-Goals

- No session management, tokens, OAuth, or JWT. Just API keys.
- No request/response body **modification** — plugins may inspect but never alter.
- No rate limiting beyond simple per-principal token bucket (no distributed/shared rate limiting).
- No TLS termination — run behind nginx/caddy for TLS.
- No ORM — `database/sql` + raw queries.

## Code Style

- `slog` for all logging. No `fmt.Println` or `log.Println`.
- Errors are values — wrap with `%w`, handle explicitly, no panics.
- Handlers as `http.Handler` / `http.HandlerFunc`, composed with middleware chaining.
- Typed context keys (`type contextKey string`) for request-scoped values.
- Minimal dependencies — prefer stdlib. See `go.mod` for the full list.
