# Threat Model

This document describes the security model of PDAG (PowerDNS Audit Gateway): what
it protects, the boundaries it enforces, the assumptions it relies on, and the
threats it does and does not defend against.

For the request flow and component diagrams see
[`architecture.md`](architecture.md); for the rationale behind specific choices
see [`design_decisions.md`](design_decisions.md). Project rules and non-goals are
in [`CLAUDE.md`](../CLAUDE.md).

## Scope

PDAG is a reverse proxy in front of the PowerDNS Authoritative API (pdAPI). It
authenticates callers with their own HMAC API keys, authorizes each request
against plugin-based policies, logs every action, and forwards permitted requests
upstream using the single static upstream API key. It does **not** modify request
or response bodies.

## Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| **HMAC signing secret(s)** | Used to verify caller API keys (`keyID:secret`). Disclosure lets an attacker forge valid keys for any principal. | Config (`hmac.keys`, keyed by `hmac_key_id`); loaded into `hmac.HmacService.secretMap`. Supports multiple keys for rotation. |
| **Upstream API key** | The single static `X-API-Key` pdAPI trusts. Disclosure bypasses PDAG entirely. | Config; injected by the proxy only on permitted, forwarded requests. |
| **Admin bearer token** | Grants access to the admin API (`:9091`) for key/principal management. Disclosure allows minting and revoking caller credentials. | Config; compared in `internal/admin` with `crypto/subtle` constant-time comparison. |
| **Audit log** | The tamper-evidence and accountability record of every action. Loss or alteration destroys the gateway's core value. | File written by `internal/audit/file.Logger` (JSON lines, append mode). |
| **Key store** | Maps key IDs to principals, roles, key hashes, expiry, and `allowed_cidrs`. Tampering grants or removes access. | SQL store (`internal/store`, migrations in `migrations/`); in-memory store is dev-only. Stores only SHA-256 HMAC **hashes**, never plaintext secrets. |

## Trust boundaries

```
 untrusted clients ──▶ [ TLS proxy ] ──▶ [ PDAG ] ──▶ [ PowerDNS pdAPI ]
   (the Internet)        (trusted)        (gateway)      (trusted)
                                             │
                                             ▼
                                     [ authz plugins ]
                                    (TRUSTED local binaries)
```

- **Untrusted → PDAG.** Clients are untrusted. Every request must present a valid
  `X-API-Key` and pass authorization. `GET /healthz` and `GET /readyz` on the
  proxy port are intentionally unauthenticated probe endpoints.
- **Fronting TLS proxy is trusted.** PDAG terminates no TLS (see Non-Goals); it
  runs behind nginx/caddy. The proxy is part of the trust boundary: it is the only
  peer permitted to assert the real client IP via `X-Forwarded-For`, and only when
  its address matches `trusted_proxies` (`internal/clientip`).
- **PDAG → PowerDNS is trusted.** The upstream pdAPI is trusted and reached over a
  private network with the static upstream key. PDAG never alters request or
  response bodies.
- **Plugins are TRUSTED local binaries.** Authorization plugins run as local
  subprocesses over hashicorp/go-plugin gRPC (`internal/authz/plugin`). They
  execute with PDAG's own privileges. A plugin author is **not** in the attacker
  model (see Out of scope); the integrity controls below defend against
  *tampering with* a trusted binary, not a *malicious* one.

## Assumptions

- TLS is terminated by a trusted fronting proxy; PDAG ↔ proxy and PDAG ↔ pdAPI
  traffic runs on a trusted/private network.
- `trusted_proxies` is configured to exactly the fronting proxy's address(es).
  Leaving it empty disables `X-Forwarded-For` parsing entirely, so `r.RemoteAddr`
  (the proxy) is used as the client IP and per-key `allowed_cidrs` become a no-op.
- The plugin directory and plugin binaries are root-owned and **not**
  group/world-writable. PDAG refuses to launch a plugin whose binary is
  group/world-writable.
- Secret-bearing files (config with HMAC keys, upstream key, admin token) have
  restrictive filesystem permissions and are readable only by the PDAG process
  user.
- The audit log destination is on durable storage with enough capacity, and log
  rotation (SIGHUP) recreates the file promptly.
- The host and operating system are trusted; PDAG does not defend against a
  compromised host, root, or other local processes able to read its memory.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| **Caller-credential theft / forgery** | Keys are `keyID:secret`; only the SHA-256 HMAC of the secret is stored, never plaintext. Verification uses HMAC-SHA256 with constant-time comparison (`hmac.Equal`) and rejects any stored hash that is not exactly one SHA-256 digest (`internal/authn/hmac`). |
| **Key enumeration / state oracle** | Every authentication failure (missing/malformed header, unknown key, bad secret, disabled, expired, IP-not-allowed) returns an **identical generic 401** ("invalid credentials"); the real reason stays in metrics/span/logs only. The secret is verified *before* any lifecycle or allowlist check, so key state is never disclosed to a caller who hasn't proven knowledge of the secret. The unknown-key path runs `DummyVerify` (equivalent HMAC work against a fixed decoy) so latency does not reveal whether a key ID exists (`internal/authn/hmac/middleware.go`). |
| **Replay** | Out of band by design — PDAG runs behind TLS, which provides transport confidentiality and integrity. There is no application-level nonce/timestamp; see Out of scope. |
| **IP spoofing via `X-Forwarded-For`** | The client IP is resolved only from `X-Forwarded-For` when the immediate peer is a configured `trusted_proxy`; otherwise `r.RemoteAddr` is used and XFF is ignored. The XFF chain is walked right-to-left and stops at the first non-trusted (or malformed) hop, so a client cannot inject a spoofed source IP to defeat per-key `allowed_cidrs` (`internal/clientip`). |
| **Plugin binary tampering / TOCTOU** | Optional per-plugin SHA-256 pin: the binary is hashed at startup and a mismatch refuses launch. Independently, PDAG refuses to exec any plugin binary that is group/world-writable (closes an RCE vector and the TOCTOU window against the hash check). The plugin parent package never imports children; wiring is centralized in `cmd/pdag/serve.go` (`internal/authz/plugin/manager.go`). |
| **Audit tampering / loss** | Fail-closed mode reserves a durable audit-buffer slot *before* the upstream call and returns 503 if the pipeline is saturated, so no audited mutation is forwarded without a committed slot. The reserved slot is committed even on a downstream panic. In fail-open mode a saturated buffer drops the entry with loud metrics (`audit_dropped_total`, `audit_write_errors_total`). On SIGHUP-driven rotation the new file is opened *before* the old one is swapped/closed; if the open fails PDAG keeps writing to the previous file rather than entering a silent audit blackout (`internal/audit`, `internal/audit/file`). |
| **Denial of service** | Request bodies are capped: a declared `Content-Length` over the limit is rejected (413) before any bytes are read, and chunked/unknown bodies are bounded by a `LimitReader` (`internal/middleware/bodybuffer.go`). Per-principal token-bucket rate limiting throttles abusive callers (`internal/ratelimit`); the admin API has its own limiter. Each authz plugin call is bounded by a per-plugin timeout and guarded by a per-plugin circuit breaker that fails closed (DENY) when open; a slow/dead plugin cannot stall requests indefinitely, and a panicking plugin call is recovered into a DENY rather than crashing the gateway. Upstream failover across balancer backends is bounded (no unbounded retry loops). |
| **Metrics / span cardinality explosion** | Attacker- or scanner-controlled paths are folded to a bounded set of route templates before being used as metric labels or span names: known PowerDNS routes have dynamic segments masked (`:server_id`, `:zone_id`, `:cryptokey_id`, `:kind`), and every unrecognized path collapses to `/other` (`internal/httproute`). |
| **Authorization bypass** | Default-deny: a request with no roles, an unconfigured role, a permanently-failed plugin, an open circuit, a timeout, an error, or a nil plugin response all yield DENY. First ALLOW wins across a caller's roles; all-DENY (or any of the above failure modes) returns 403 (`internal/authz`). |
| **Admin-token brute force / timing** | The bearer token is compared in constant time (`crypto/subtle`); the admin API is bound to a separate port (`:9091`) and rate-limited. |

## Non-goals / out of scope

These are deliberate boundaries, not gaps:

- **TLS termination.** PDAG performs none; run it behind nginx/caddy. Transport
  confidentiality, integrity, and replay resistance are delegated to that layer.
- **A malicious plugin author.** Plugins are trusted local binaries that run with
  PDAG's privileges **by design**. The SHA-256 pin and writable-file check defend
  against tampering with a trusted binary, not against an operator deliberately
  installing a hostile one. Vetting plugin source/supply chain is the operator's
  responsibility.
- **Request/response body modification.** Plugins may inspect bodies but never
  alter them; PDAG forwards bodies verbatim.
- **Distributed / shared rate limiting.** Rate limiting is per-process
  (per-principal token bucket) only. A multi-instance deployment does not enforce
  a global limit.
- **Sessions, OAuth, JWT, tokens.** Authentication is API keys only.
- **Host / OS compromise.** PDAG does not defend against a compromised host, a
  malicious root user, or another local process reading its memory or secret
  files.
- **Application-level replay nonces.** Not implemented; replay protection relies
  on the TLS layer.
