# PDAG — PowerDNS Audit Gateway

A lightweight, performant reverse proxy in Go that sits in front of the PowerDNS Authoritative API (pdAPI). It adds audit logging and role-based access control without modifying or redefining the upstream API.

For architecture diagrams see [`docs/architecture.md`](docs/architecture.md).  
For design decisions see [`docs/design_decisions.md`](docs/design_decisions.md).  
For contributing guidelines see [`docs/contributing.md`](docs/contributing.md).

## Problem

The PowerDNS API authenticates via a single static `X-API-Key` header. There is no concept of multiple users, roles, permissions, or audit trails. PDAG solves this by intercepting requests, authenticating callers with their own credentials, authorizing against plugin-based policies, logging every action, and forwarding permitted requests upstream with the real static API key.

## Non-Goals

- No session management, tokens, OAuth, or JWT. Just API keys.
- No request/response body **modification** — plugins may inspect but never alter.
- No rate limiting beyond simple per-principal token bucket (no distributed/shared rate limiting).
- No TLS termination — run behind nginx/caddy for TLS.
- No ORM — `database/sql` + raw queries.
