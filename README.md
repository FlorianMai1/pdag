# PDAG — PowerDNS Audit Gateway

PDAG is a lightweight, high-performance reverse proxy in Go that sits in front of the
[PowerDNS Authoritative API](https://doc.powerdns.com/authoritative/http-api/). The
PowerDNS API authenticates with a single static `X-API-Key` and has no concept of
users, roles, or audit trails. PDAG fixes that without changing the upstream API: it
authenticates each caller with their own HMAC-derived API key, authorizes the request
against plugin-based policies, writes an audit record for every action, and forwards
permitted requests upstream with the real static API key.

## Features

- **Per-caller API keys** — HMAC-derived `keyID:secret` credentials, hashed at rest,
  with optional expiry, per-key CIDR allowlists, enable/disable, and rotation.
- **Pluginbased RBAC** — roles map 1:1 to authorization plugins (gRPC over
  [hashicorp/go-plugin](https://github.com/hashicorp/go-plugin)). First `ALLOW` across a
  caller's roles wins; all-`DENY` returns `403`.
- **Plugin hardening** — optional per-plugin SHA-256 binary pinning, per-plugin
  timeouts, and circuit breakers.
- **Audit logging** — JSONL audit trail with optional request-body capture, field
  redaction, and a fail-closed mode that refuses traffic rather than lose records.
- **Upstream resilience** — multiple PowerDNS backends with active health checks and
  load balancing.
- **Operability** — Prometheus metrics, OpenTelemetry tracing, graceful shutdown,
  per-principal rate limiting, and liveness/readiness probes.
- **Config-driven** — single annotated YAML file with environment-variable overrides.

## Architecture

PDAG runs three HTTP servers: the **proxy** (`:8080`) handles authenticated DNS-API
traffic and serves the health probes; **metrics** (`:9090`) exposes Prometheus; and the
**admin API** (`:9091`) manages keys behind a bearer token. Incoming requests are
authenticated, authorized through the caller's role plugins, audited, and then forwarded
upstream with the static PowerDNS API key. Bodies are inspected by plugins but never
modified.

For diagrams, the request lifecycle, and the full admin endpoint table see
[`docs/architecture.md`](docs/architecture.md). For the rationale behind key choices see
[`docs/design_decisions.md`](docs/design_decisions.md).

## Quickstart

### 1. Build

```sh
make all          # builds bin/pdag plus the five bundled plugins
```

### 2. Configure

```sh
cp pdag.yaml.example pdag.yaml
# edit pdag.yaml: set admin_token, hmac_secrets, and upstream api_key
```

### 3. Run with Docker Compose

The bundled [`docker-compose.yml`](docker-compose.yml) brings up PowerDNS (with its
PostgreSQL backend), a PostgreSQL database for PDAG, and PDAG itself (ports `8080`,
`9090`, `9091`). DB migrations are applied automatically at startup.

```sh
docker compose up -d
curl http://localhost:8080/healthz   # -> ok
```

### 4. Create an API key

Via the CLI (requires `db.dsn` to be set in `pdag.yaml`):

```sh
bin/pdag key create --config pdag.yaml --principal alice --roles read_zones,admin
```

Or via the admin API:

```sh
curl -X POST http://localhost:9091/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"principal":"alice","roles":["read_zones","admin"]}'
```

Either way you receive a `keyID:secret` pair. The secret is shown only once.

### 5. Send a request

```sh
curl http://localhost:8080/api/v1/servers/localhost/zones \
  -H "X-API-Key: <keyID>:<secret>"
```

## Configuration

[`pdag.yaml.example`](pdag.yaml.example) is the canonical, fully annotated reference for
every option (listen addresses, upstreams, audit log, HMAC secrets, rate limiting,
tracing, and plugins). Configuration loads via [viper](https://github.com/spf13/viper):
values come from the YAML file and can be overridden by `PDAG_`-prefixed environment
variables. Validate a config without starting the server with `pdag validate --config
pdag.yaml`.

## Servers and health endpoints

| Server  | Default | Auth         | Purpose                                         |
| ------- | ------- | ------------ | ----------------------------------------------- |
| Proxy   | `:8080` | per-key HMAC | DNS-API traffic + `GET /healthz`, `GET /readyz` |
| Metrics | `:9090` | none         | Prometheus scrape endpoint                      |
| Admin   | `:9091` | bearer token | Key lifecycle management                        |

`GET /healthz` is an unauthenticated liveness probe. `GET /readyz` is an unauthenticated
readiness probe that checks dependencies (key store, plugins, and upstream availability).

## CLI

The `pdag` binary exposes four subcommands:

- `pdag serve` — run the gateway (the three servers above).
- `pdag key` — manage API keys: `create`, `list`, `enable`, `disable`, `delete` (uses the
  database configured in `pdag.yaml`).
- `pdag validate` — load and validate a config file, then exit.
- `pdag version` — print build version, commit, and date.

## Plugins

Authorization is delegated to plugins: each configured plugin name is a role, and a key's
roles select which plugins evaluate its requests. Plugins are separate binaries that
implement the `Authorizer` interface from the [`sdk/`](sdk) package and communicate over
gRPC; they may inspect the request (method, path, body) but never modify it. Five plugins
ship with PDAG (`admin`, `read_zones`, `zone_notify`, `letsencrypt_dns_challenger`,
`api_discovery`). For how to write, build, and pin a plugin see
[`docs/plugins.md`](docs/plugins.md).

## Observability

PDAG exposes Prometheus metrics on the metrics server (`:9090`) covering request rates,
latencies, authorization decisions, audit pipeline health, and circuit-breaker state.
OpenTelemetry tracing can be enabled in the `tracing` section of the config to export
spans to an OTLP collector. See [`docs/metrics.md`](docs/metrics.md) for the metric
catalogue and dashboard guidance.

## Security

Report vulnerabilities per [`SECURITY.md`](SECURITY.md). Some capabilities are
**deliberate non-goals** and must be provided by your surrounding infrastructure:

- **No TLS termination** — run PDAG behind nginx or Caddy for TLS.
- **No distributed rate limiting** — rate limiting is per-process only.
- **No request/response body modification** — plugins inspect but never alter bodies.
- **No sessions, OAuth, or JWT** — authentication is API keys only.

## Development

```sh
make check   # fix + fmt + vet + lint + test (-race) + govulncheck
```

Run `make check` before committing. Integration tests (Docker required) run with
`make test-integration`. Contribution guidelines, coding rules, and the component model
are in [`docs/contributing.md`](docs/contributing.md) and [`CLAUDE.md`](CLAUDE.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
