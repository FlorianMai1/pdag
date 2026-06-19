# ── Build stage ───────────────────────────────────────────────────
# Pin by digest in production, e.g. golang:1.26-alpine@sha256:<digest>.
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version metadata injected at link time (pass with --build-arg).
ARG VERSION=docker
ARG COMMIT=none
ARG DATE=unknown
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /pdag ./cmd/pdag
RUN for p in admin read_zones letsencrypt_dns_challenger zone_notify api_discovery; do \
      go build -trimpath -o /plugins/$p ./plugins/$p; \
    done

# ── Runtime stage ─────────────────────────────────────────────────
# Pin by digest in production, e.g. alpine:3.20@sha256:<digest>.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
    && adduser -D -H -u 10001 pdag

# Plugin binaries stay root-owned and non-writable by the pdag user: the plugin
# manager refuses to launch a group/world-writable binary (RCE/TOCTOU guard).
COPY --from=build /pdag /usr/local/bin/pdag
COPY --from=build --chmod=0755 /plugins /opt/pdag/plugins
COPY migrations /opt/pdag/migrations

# Pre-create the audit-log dir owned by the runtime user so a freshly-created
# named volume mounted here inherits that ownership (volumes copy the image
# dir's ownership on first init).
RUN mkdir -p /var/log/pdag && chown 10001:10001 /var/log/pdag

WORKDIR /opt/pdag
USER pdag
EXPOSE 8080 9090 9091

# Liveness probe against the proxy server's unauthenticated /healthz.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["pdag"]
CMD ["serve"]
