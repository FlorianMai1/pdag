# Security Policy

PDAG (PowerDNS Audit Gateway) is a reverse proxy that adds authentication,
authorization, and audit logging in front of the PowerDNS Authoritative API.
Because it gatekeeps DNS administration, its security posture is a first-class
concern. This document describes how to report vulnerabilities, the security
model, and the hardening we expect of operators.

> **Use at your own risk.** This is a personal, best-effort project provided
> "as is", without warranty of any kind and with no guaranteed support, SLA, or
> coordinated-disclosure process (see the Apache-2.0 [`LICENSE`](LICENSE)).
> Evaluate it yourself before relying on it.

For the full attacker-model analysis and per-component trust boundaries, see
[`docs/threat_model.md`](docs/threat_model.md). For architecture and the request
flow see [`docs/architecture.md`](docs/architecture.md); for the reasoning behind
the security-relevant trade-offs see [`docs/design_decisions.md`](docs/design_decisions.md).

## Supported Versions

PDAG is **pre-1.0** and does not yet publish stable releases. Only the latest
`main` is the supported line — security fixes land on `main`, and there are no
backports to older commits or tags. Operators should track `main` and rebuild
to pick up fixes. Once 1.0 ships, this section will be replaced with a concrete
version-support matrix.

| Version | Supported |
|---------|-----------|
| `main` (latest) | Yes |
| Anything older  | No  |

## Reporting a Vulnerability

Found a security issue? Either is fine:

- **Open a GitHub issue** on this repository, or
- **Email the maintainer** at the address on the
  [@FlorianMai1](https://github.com/FlorianMai1) GitHub profile.

There is no embargo or formal coordinated-disclosure process — this is a
hobby project, so reports are handled on a best-effort basis with no guaranteed
response time. A helpful report includes the affected component (proxy, admin
API, a plugin, the audit pipeline, …), steps to reproduce, and the commit hash
you saw it on.

## Security Model

PDAG exists because the upstream PowerDNS API authenticates with a single static
`X-API-Key` and has no notion of users, roles, or audit trails. PDAG terminates
caller credentials, authorizes the request, records it, and only then forwards
it upstream with the real static key. The defenses that make this trustworthy:

- **HMAC API-key authentication.** Callers present `X-API-Key: <id>:<secret>`.
  PDAG looks up the key by id and verifies an HMAC-SHA256 over the secret; the
  raw secret is never stored. See the authn step in the
  [request flow](docs/architecture.md#request-flow--middleware-chain).
- **Plugin-based RBAC.** Each caller has roles that map 1:1 to authorization
  plugins. Requests are fanned out over gRPC to the plugins for the caller's
  roles; **the first `ALLOW` wins, and all-`DENY` yields `403`**. Plugins may
  **inspect** the request but are contractually forbidden from **modifying** the
  request or response body — PDAG does not redefine the upstream API.
- **Audit trail.** Every authenticated action is logged as a JSON line
  (principal, key id, roles, method, path, source IP, upstream status, and
  optionally a size-capped, field-redacted body).
- **Fail-closed audit option.** With `audit_fail_closed: true`, PDAG returns
  `503` rather than forward an action upstream when the audit pipeline is
  saturated, so no audited action proceeds without a durable record. This trades
  availability for audit completeness.
- **Trusted-proxy client IP.** When run behind a fronting proxy, set
  `trusted_proxies` so the client IP for per-key `allowed_cidrs` checks and the
  audit `source_ip` is taken from `X-Forwarded-For` at the rightmost untrusted
  hop. If left empty, `X-Forwarded-For` is ignored and the immediate peer is
  used, so the client IP cannot be spoofed.
- **Plugin SHA256 pinning and the non-writable requirement.** Each plugin may be
  pinned with a `sha256` digest; startup fails on mismatch. Plugins execute as
  local subprocesses, so the plugin directory and binaries must be
  root-owned and **non-writable** by the PDAG runtime user — otherwise pinning
  is meaningless and a writable plugin is arbitrary code execution.
- **Secrets via files.** The upstream API key, the admin bearer token, and
  similar secrets can be sourced from files (`*_file` options) instead of inline
  config. Keep these files tightly permissioned (`0600`, owned by the runtime
  user) and out of version control; treat inline secrets in `pdag.yaml` as a
  development convenience only.

## Hardening Expectations for Operators

PDAG ships secure-by-default where it can, but several controls are the
operator's responsibility:

- **Firewall the metrics and admin ports.** The Prometheus metrics server
  (`:9090`) and the admin API (`:9091`) are **not** intended for public
  exposure. Restrict them to your monitoring and operations networks via
  firewall rules or network policy. The admin API is bearer-token protected, but
  the token is a single shared secret — do not rely on it as your only barrier.
- **Terminate TLS at a fronting proxy.** PDAG does **not** terminate TLS by
  design. Run it behind nginx/caddy (or equivalent) for TLS, and configure
  `trusted_proxies` to match that proxy so client-IP handling is correct.
- **Run as the provided non-root user.** Use the non-root user the container
  image ships with. Do not run PDAG as root; it does not need elevated
  privileges to operate.
- **Keep the plugin directory root-owned and non-writable.** The directory
  holding plugin binaries (e.g. `/opt/pdag/plugins`) must be owned by root and
  not writable by the PDAG runtime user. Combined with `sha256` pinning, this
  prevents tampering or substitution of the authorization logic.
- **Protect the audit log and secret files.** Ensure the audit log path and any
  `*_file` secrets are on a volume the runtime user can read/write as needed but
  that is otherwise tightly permissioned, and ship audit logs to durable,
  append-only storage.

See [`docs/threat_model.md`](docs/threat_model.md) for the threats these
expectations mitigate and the residual risks that remain.
