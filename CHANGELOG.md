# Changelog

All notable changes to PDAG are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This entry covers the 2026-06 hardening pass: a 66-finding security/correctness
review (4 high, 10 medium, 20 low, 12 nit) was fully remediated, plus
release-readiness work.

### Security
- Bump gRPC to v1.79.3 to fix **GO-2026-4762** (authorization bypass in gRPC-Go),
  reachable via the plugin authz transport. `govulncheck` is now part of `make check`.
- Authn returns a uniform `401 invalid credentials` for every failure (unknown
  key, bad secret, disabled, expired, IP-not-allowed) and verifies the HMAC
  secret before evaluating key state, closing a key-state/enumeration oracle; a
  dummy HMAC equalizes the unknown-key timing path.
- New opt-in `trusted_proxies` resolves the real client IP from `X-Forwarded-For`
  for the per-key `allowed_cidrs` check and audit `source_ip` (spoof-safe).
- Plugin binaries are rejected if group/world-writable; SHA256 pin compared
  case-insensitively.
- Sensitive headers (`Authorization`, `Cookie`, `Proxy-Authorization`,
  `X-Api-Key`) are redacted before requests are fanned out to plugins.
- Optional audit request-body logging now caps size (`audit_body_max_bytes`) and
  redacts configured JSON fields (`audit_redact_fields`).

### Added
- Opt-in fail-closed audit mode (`audit_fail_closed`): reserve a buffer slot
  before proxying and return 503 if the audit pipeline is saturated, so no
  audited action is forwarded without a durable record. Default mode does a
  bounded-blocking enqueue (`audit_enqueue_timeout`).
- Bounded request-level failover in the load balancer for idempotent methods.
- `pdag version` subcommand and build metadata stamped via `-ldflags`; version
  logged at startup.
- Metrics: `audit_inconsistency_total`, `audit_reopen_failures_total`.
- Docs: README, SECURITY.md, threat model, metrics catalog, plugin-authoring
  guide; CI workflow; `govulncheck` and version stamping in the build.
- Non-root, HEALTHCHECK-enabled Docker image.

### Fixed
- Audit log no longer silently drops entries under back-pressure (bounded block)
  and survives a failed SIGHUP reopen without a permanent blackout.
- Plugin cancellation no longer trips sibling circuit breakers; a nil plugin
  response or panic can no longer crash the gateway.
- Graceful shutdown tears down all servers on a startup error; `shutdown_wait`
  is validated.
- Prometheus path-label cardinality is bounded (unknown paths fold to `/other`).
- Admin API: strict JSON decoding, role/CIDR validation, past-expiry rejection,
  and audit/mutation consistency (compensating delete + reconciliation metric).
- Numerous robustness fixes: body-size early reject, rate-limiter eviction,
  pgarray NULL/whitespace handling, memory-store paging bounds, and more.

[Unreleased]: https://github.com/mai/pdag/compare/main...HEAD
