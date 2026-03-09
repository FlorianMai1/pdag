# ── Build stage ───────────────────────────────────────────────────
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /pdag ./cmd/pdag
RUN CGO_ENABLED=0 go build -o /plugins/admin    ./plugins/admin
RUN CGO_ENABLED=0 go build -o /plugins/read_zones ./plugins/read_zones
RUN CGO_ENABLED=0 go build -o /plugins/letsencrypt_dns_challenger ./plugins/letsencrypt_dns_challenger
RUN CGO_ENABLED=0 go build -o /plugins/zone_notify ./plugins/zone_notify

# ── Runtime stage ─────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /pdag /usr/local/bin/pdag
COPY --from=build /plugins /opt/pdag/plugins
COPY migrations /opt/pdag/migrations

WORKDIR /opt/pdag
EXPOSE 8080 9090
ENTRYPOINT ["pdag"]
CMD ["serve"]
