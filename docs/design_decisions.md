# Design Decisions

### Plugin-based authorization

Regex + method matching is not expressive enough. Roles often need to inspect the request body and make domain-aware decisions. For example, `letsencrypt_dns_challenger` must verify that a PATCH only touches TXT records with an `_acme-challenge.` prefix — and may resolve the FQDN to confirm an A/AAAA record exists.

**Each role is a standalone plugin binary** using [HashiCorp go-plugin](https://github.com/hashicorp/go-plugin) over gRPC:

- **Domain logic isolation** — each plugin is its own binary with its own dependencies. A crash does not bring down PDAG.
- **Independent deployability** — add or update a role by dropping a new binary. No PDAG recompile needed.
- **Full request introspection** — plugins receive method, path, headers, and the full buffered request body via protobuf (see `proto/authz/authz.proto`).

### Circuit breaker per plugin

A single misbehaving plugin must never degrade the entire gateway. Each plugin has a per-call timeout (default 500ms) and a per-plugin circuit breaker (closed → open → half-open). Configuration is per-plugin with global defaults (see `plugin_defaults` in config).

### HMAC-SHA256 over argon2/bcrypt for key hashing

API keys are high-entropy machine-generated secrets (32+ random bytes), not user-chosen passwords. Brute-force is infeasible regardless of hash speed. HMAC-SHA256 keeps verification on the hot path cheap (sub-microsecond vs ~100ms for argon2). The HMAC secret lives in config/env, **not** in the database — a DB leak alone is insufficient to verify candidate keys.

### HMAC secret rotation

Each key row stores an `hmac_key_id` indicating which secret produced its hash. Config supports a list of HMAC secrets (first = current for new keys, rest = still accepted for verification). This allows rotating the HMAC secret without invalidating all keys at once.

### Request body buffering (store-and-forward)

Request bodies are buffered into memory (up to `max_body_size`, default 1 MiB) before dispatching to plugins, then restored on `r.Body` for proxying. Requests exceeding the limit get 413.

### Header stripping on proxy

All client-supplied headers are stripped from the outbound request to prevent header injection into pdAPI. Only `X-API-Key` (real upstream key), `Host`, `Content-Type`, `Content-Length`, and `Accept` are set on the proxied request.

### Two separate log streams

- **Application log** (stderr, `slog`) — operational: startup, config reload, plugin lifecycle, circuit breaker transitions, errors. `SanitizeHeaders()` redacts `X-Api-Key` values before any log output.
- **Audit log** (dedicated JSON lines file) — one structured entry per request for compliance/forensics. Logged after proxying so the upstream status code is available. Reopened on SIGHUP for log rotation.

### Fail fast on invalid config

PDAG validates all configuration at startup and refuses to start if anything is invalid. This includes listen address format, `MaxBodySize > 0`, HMAC secret minimum length (16 bytes), circuit breaker thresholds, rate limit values when enabled, health check `timeout < interval` for multi-backend setups, and non-empty DSN when using postgres. Port conflicts between proxy/metrics/admin produce a warning. The principle: a bad config should be caught at deploy time, not as a mysterious runtime failure.

### No background cleanup — operator-driven operations

PDAG does not run background jobs for housekeeping (e.g., purging expired keys, rotating secrets). Instead, it exposes explicit admin API endpoints that operators call on their own schedule — via cron, CI/CD, or manual invocation. This keeps PDAG's behavior fully predictable: it does exactly what it's told, when it's told, with no hidden timers or implicit state changes.

### Lock-free hot path in plugin manager

The plugin manager uses `atomic.Pointer[pluginMap]` with copy-on-write for the plugin instance map. The hot path (`Authorize`, `Healthy`, `HasPlugins`) performs a single atomic pointer load — no mutexes, no contention. Writers (`restartPlugin`, `Close`) serialize via a separate `sync.Mutex` and perform copy-on-write: load → copy → modify → atomic store.