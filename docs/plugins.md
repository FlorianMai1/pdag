# Writing PDAG Authorization Plugins

PDAG delegates every authorization decision to plugins. Each plugin is a
standalone executable that PDAG launches and talks to over gRPC using
[hashicorp/go-plugin](https://github.com/hashicorp/go-plugin). A plugin receives
a redacted copy of the incoming HTTP request and returns `ALLOW` or `DENY` with a
human-readable reason. Plugins **inspect** requests only — they can never modify
the request or response body (see [Non-Goals in CLAUDE.md](../CLAUDE.md) and
[design decisions](design_decisions.md#plugin-based-authorization)).

For where plugins sit in the request lifecycle, see the
[Plugin Authorization Flow](architecture.md#plugin-authorization-flow) diagram.

## The `Authorizer` interface

Plugins implement a single method, defined in [`sdk/plugin.go`](../sdk/plugin.go):

```go
type Authorizer interface {
    Authorize(ctx context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error)
}
```

- `ctx` carries the per-call deadline (the plugin `timeout`, see below). Honor it
  if you do any I/O.
- Return a non-nil `*pb.AuthorizeResponse`. Returning a non-nil `error` is treated
  as a plugin failure (it counts toward the circuit breaker), not as a `DENY`;
  use `Decision_DENY` to deny.

## Minimal `main()`

`sdk.Serve` wires up the gRPC handshake and serves your implementation. A complete
plugin is just this:

```go
// Plugin example denies everything except GET /healthz.
package main

import (
    "context"

    pb "github.com/mai/pdag/proto/authz"
    "github.com/mai/pdag/sdk"
)

type plugin struct{}

func (p *plugin) Authorize(_ context.Context, req *pb.HttpRequest) (*pb.AuthorizeResponse, error) {
    if req.Method == "GET" && req.Path == "/healthz" {
        return &pb.AuthorizeResponse{
            Decision: pb.Decision_ALLOW,
            Reason:   "example: health check",
        }, nil
    }
    return &pb.AuthorizeResponse{
        Decision: pb.Decision_DENY,
        Reason:   "example: not permitted",
    }, nil
}

func main() {
    sdk.Serve(&plugin{})
}
```

See [`plugins/read_zones/main.go`](../plugins/read_zones/main.go) for the canonical
small example (allow `GET` on the zones endpoints, deny everything else).

## What `HttpRequest` contains

The request is the `HttpRequest` protobuf from
[`proto/authz/authz.proto`](../proto/authz/authz.proto):

| Field | Notes |
| --- | --- |
| `method` | HTTP method, e.g. `GET`, `PATCH`. |
| `path` | URL path, e.g. `/api/v1/servers/localhost/zones`. |
| `raw_query` | Raw query string (un-decoded). |
| `scheme`, `host` | From the inbound request. |
| `headers` | `repeated Header` (key + multi-valued). HTTP headers are multi-valued, so this is not a map. |
| `body` | The buffered request body bytes (see below). |
| `content_length` | Original `Content-Length`. |
| `remote_addr` | Peer `ip:port`. |
| `request_id` | PDAG-assigned correlation ID (also in the audit log). |
| `principal` | The authenticated caller, resolved by the authn step. |

### Redacted headers

Credential-bearing headers are replaced with the single value `REDACTED` before
the request is fanned out to plugins, so secrets never reach plugin binaries. The
redacted set (canonical form) is `X-Api-Key`, `Authorization`, `Cookie`, and
`Proxy-Authorization`. Do not rely on these for decisions — authentication has
already happened upstream and the caller is in `principal`. See
[header stripping](design_decisions.md#header-stripping-on-proxy).

### Body buffering

PDAG buffers the request body up to the global `max_body_size` (default 1 MiB in
[`pdag.yaml.example`](../pdag.yaml.example)) so plugins can inspect it; requests
exceeding the limit are rejected before reaching plugins. The same buffered bytes
are then forwarded upstream unchanged (store-and-forward — see
[request body buffering](design_decisions.md#request-body-buffering-store-and-forward)).
`body` may be empty for bodyless requests.

## Returning a decision

Return an `AuthorizeResponse` with a `Decision` of `Decision_ALLOW` or
`Decision_DENY` and a `reason`. The `reason` is human-readable and is recorded in
the audit log, so make it specific (e.g. `"read_zones: path not allowed"`) — it is
your primary debugging signal for why a request was allowed or denied.

## Registering a plugin

Roles map **1:1** to plugin names. A plugin named under `plugins:` is the role of
the same name; keys are then granted that role. Configure plugins in
[`pdag.yaml.example`](../pdag.yaml.example):

```yaml
plugin_defaults:
  timeout: 500ms
  circuit_breaker:
    failure_threshold: 5
    success_threshold: 2
    cooldown: 30s

plugins:
  read_zones:
    path: "/opt/pdag/plugins/read_zones"
  letsencrypt_dns_challenger:
    path: "/opt/pdag/plugins/letsencrypt_dns_challenger"
    sha256: "<64-hex-digest>"   # optional: pin the binary; startup fails on mismatch
    timeout: 2s                 # per-plugin override (DNS may be slow)
    circuit_breaker:            # per-plugin override
      failure_threshold: 3
      cooldown: 60s
```

- **`path`** — absolute path to the built plugin binary (required).
- **`sha256`** — optional hex digest pin. PDAG verifies it at startup and refuses
  to start on mismatch.
- **`timeout`** and **`circuit_breaker`** — optional per-plugin overrides;
  anything omitted falls back to `plugin_defaults`.

### Decision aggregation: first-ALLOW-wins

A caller may hold several roles, hence several plugins. PDAG fans the request out
to all of the caller's plugins; the **first `ALLOW` wins** and the request is
forwarded upstream. If every plugin returns `DENY` (or a caller has no roles), the
request is rejected with **`403 Forbidden`**. Design each plugin to make its own
narrow, independent decision — it does not see other plugins' verdicts.

## Operational behavior

- **Binary permissions.** The plugin binary must **not** be writable by group or
  other; PDAG checks the file mode at startup and refuses to launch a
  group/world-writable binary (`make it non-writable`). The binary is exec'd with
  the gateway's privileges, so this prevents tampering.
- **Crash isolation + auto-restart.** Plugins run as separate processes. A crash
  is isolated from the gateway and other plugins, and PDAG automatically restarts
  the plugin. After repeated restart failures the plugin is marked permanently
  failed and its calls deny.
- **Per-call timeout.** Each `Authorize` call is bounded by the effective
  `timeout`; exceeding it counts as a failure.
- **Circuit breaker.** Per-plugin failures (errors, timeouts, crashes) trip a
  circuit breaker (`failure_threshold` / `success_threshold` / `cooldown`); while
  open, the plugin's calls fail fast. See
  [circuit breaker per plugin](design_decisions.md#circuit-breaker-per-plugin).

## Building a plugin

Put the package under `plugins/<name>/` with a `main.go` like the skeleton above,
then add `<name>` to the `PLUGINS` list in the [`Makefile`](../Makefile).

```sh
make plugins         # build all plugins into bin/plugins/
make <name>          # build a single plugin
make all             # build pdag + all plugins
make check           # fmt + vet + lint + race tests + govulncheck
```

Point the plugin's `path` in `pdag.yaml` at the built binary (e.g.
`bin/plugins/<name>`), assign the matching role to a key, and the plugin is live.
See [contributing guidelines](contributing.md) before opening a PR.
